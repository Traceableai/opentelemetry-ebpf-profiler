// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package tracer contains functionality for populating tracers.
package tracer // import "go.opentelemetry.io/ebpf-profiler/tracer"

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/ebpf/perf"
	"go.opentelemetry.io/ebpf-profiler/periodiccaller"
	"go.opentelemetry.io/ebpf-profiler/process"
	"os"
	"sync/atomic"
	"time"
	"unsafe"

	cebpf "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"github.com/zeebo/xxh3"

	"go.opentelemetry.io/ebpf-profiler/host"
	"go.opentelemetry.io/ebpf-profiler/libpf"
	"go.opentelemetry.io/ebpf-profiler/nativeunwind/elfunwindinfo"
	"go.opentelemetry.io/ebpf-profiler/proc"
	pm "go.opentelemetry.io/ebpf-profiler/processmanager"
	pmebpf "go.opentelemetry.io/ebpf-profiler/processmanager/ebpf"
	"go.opentelemetry.io/ebpf-profiler/reporter"
	"go.opentelemetry.io/ebpf-profiler/support"
	"go.opentelemetry.io/ebpf-profiler/times"
	"go.opentelemetry.io/ebpf-profiler/tracehandler"
	"go.opentelemetry.io/ebpf-profiler/tracer/types"
)

/*
#include <stdint.h>
#include "../support/ebpf/types.h"
*/
import "C"

// Tracer provides an interface for loading and initializing the eBPF components as
// well as for monitoring the output maps for new traces and count updates.
type CustomTracer struct {
	fallbackSymbolHit  atomic.Uint64
	fallbackSymbolMiss atomic.Uint64

	// ebpfMaps holds the currently loaded eBPF maps.
	ebpfMaps map[string]*cebpf.Map
	// ebpfProgs holds the currently loaded eBPF programs.
	ebpfProgs map[string]*cebpf.Program

	// kernelSymbols is used to hold the kernel symbol addresses we are tracking
	kernelSymbols *libpf.SymbolMap

	// kernelModules holds symbols/addresses for the kernel module address space
	kernelModules *libpf.SymbolMap

	// hooks holds references to loaded eBPF hooks.
	hooks map[hookPoint]link.Link

	// processManager keeps track of loading, unloading and organization of information
	// that is required to unwind processes in the kernel. This includes maintaining the
	// associated eBPF maps.
	processManager *pm.ProcessManager

	// triggerPIDProcessing is used as manual trigger channel to request immediate
	// processing of pending PIDs. This is requested on notifications from eBPF code
	// when process events take place (new, exit, unknown PC).
	triggerPIDProcessing chan bool

	// pidEvents notifies the tracer of new PID events.
	// It needs to be buffered to avoid locking the writers and stacking up resources when we
	// read new PIDs at startup or notified via eBPF.
	pidEvents chan libpf.PID

	// intervals provides access to globally configured timers and counters.
	intervals Intervals

	// moduleFileIDs maps kernel module names to their respective FileID.
	moduleFileIDs map[string]libpf.FileID

	// reporter allows swapping out the reporter implementation.
	reporter reporter.SymbolReporter
}

// NewTracer loads eBPF code and map definitions from the ELF module at the configured path.
func NewCustomTracer(ctx context.Context, cfg *Config) (*CustomTracer, error) {
	kernelSymbols, err := proc.GetKallsyms("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel symbols: %v", err)
	}

	// Based on includeTracers we decide later which are loaded into the kernel.
	ebpfMaps, ebpfProgs, err := initializeCustomMapsAndPrograms(kernelSymbols, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF code: %v", err)
	}

	ebpfHandler, err := pmebpf.LoadMaps(ctx, ebpfMaps)
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF maps: %v", err)
	}

	processManager, err := pm.New(ctx, cfg.IncludeTracers, cfg.Intervals.MonitorInterval(),
		ebpfHandler, nil, cfg.Reporter, elfunwindinfo.NewStackDeltaProvider(),
		cfg.FilterErrorFrames)
	if err != nil {
		return nil, fmt.Errorf("failed to create processManager: %v", err)
	}

	const fallbackSymbolsCacheSize = 16384

	kernelModules, err := proc.GetKernelModules("/proc/modules", kernelSymbols)
	if err != nil {
		return nil, fmt.Errorf("failed to read kernel modules: %v", err)
	}

	moduleFileIDs, err := processKernelModulesMetadata(cfg.Reporter, kernelModules, kernelSymbols)
	if err != nil {
		return nil, fmt.Errorf("failed to extract kernel modules metadata: %v", err)
	}

	return &CustomTracer{
		fallbackSymbolHit:    atomic.Uint64{},
		fallbackSymbolMiss:   atomic.Uint64{},
		ebpfMaps:             ebpfMaps,
		ebpfProgs:            ebpfProgs,
		kernelSymbols:        kernelSymbols,
		kernelModules:        kernelModules,
		hooks:                make(map[hookPoint]link.Link),
		processManager:       processManager,
		triggerPIDProcessing: make(chan bool, 1),
		pidEvents:            make(chan libpf.PID, pidEventBufferSize),
		intervals:            cfg.Intervals,
		moduleFileIDs:        moduleFileIDs,
		reporter:             cfg.Reporter,
	}, nil
}

// Close provides functionality for Tracer to perform cleanup tasks.
// NOTE: Close may be called multiple times in succession.
func (t *CustomTracer) Close() {
	// Avoid resource leakage by closing all kernel hooks.
	for hookPoint, hook := range t.hooks {
		if err := hook.Close(); err != nil {
			log.Errorf("Failed to close '%s/%s': %v", hookPoint.group, hookPoint.name, err)
		}
		delete(t.hooks, hookPoint)
	}

	t.processManager.Close()
}

// initializeCustomMapsAndPrograms loads the definitions for the eBPF maps and programs provided
// by the embedded elf file and loads these into the kernel.
func initializeCustomMapsAndPrograms(kernelSymbols *libpf.SymbolMap, cfg *Config) (
	ebpfMaps map[string]*cebpf.Map, ebpfProgs map[string]*cebpf.Program, err error) {
	// Loading specifications about eBPF programs and maps from the embedded elf file
	// does not load them into the kernel.
	// A collection specification holds the information about eBPF programs and maps.
	// References to eBPF maps in the eBPF programs are just placeholders that need to be
	// replaced by the actual loaded maps later on with RewriteMaps before loading the
	// programs into the kernel.
	coll, err := support.LoadCollectionSpec(cfg.DebugTracer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load specification for tracers: %v", err)
	}
	fmt.Printf("progs: %v\n", coll.Programs)
	fmt.Printf("maps: %v\n", coll.Maps)

	err = buildStackDeltaTemplates(coll)
	if err != nil {
		return nil, nil, err
	}

	ebpfMaps = make(map[string]*cebpf.Map)
	ebpfProgs = make(map[string]*cebpf.Program)

	// Load all maps into the kernel that are used later on in eBPF programs. So we can rewrite
	// in the next step the placesholders in the eBPF programs with the file descriptors of the
	// loaded maps in the kernel.
	if err = loadAllMaps(coll, cfg, ebpfMaps); err != nil {
		return nil, nil, fmt.Errorf("failed to load eBPF maps: %v", err)
	}

	// Replace the place holders for map access in the eBPF programs with
	// the file descriptors of the loaded maps.
	//nolint:staticcheck
	if err = coll.RewriteMaps(ebpfMaps); err != nil {
		return nil, nil, fmt.Errorf("failed to rewrite maps: %v", err)
	}

	if cfg.KernelVersionCheck {
		var major, minor, patch uint32
		major, minor, patch, err = GetCurrentKernelVersion()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get kernel version: %v", err)
		}
		if hasProbeReadBug(major, minor, patch) {
			if err = checkForMaccessPatch(coll, ebpfMaps, kernelSymbols); err != nil {
				return nil, nil, fmt.Errorf("your kernel version %d.%d.%d may be "+
					"affected by a Linux kernel bug that can lead to system "+
					"freezes, terminating host agent now to avoid "+
					"triggering this bug.\n"+
					"If you are certain your kernel is not affected, "+
					"you can override this check at your own risk "+
					"with -no-kernel-version-check.\n"+
					"Error: %v", major, minor, patch, err)
			}
		}
	}

	tailCallProgs := []progLoaderHelper{
		{
			progID: uint32(support.ProgUnwindStop),
			name:   "unwind_stop",
			enable: true,
		},
		{
			progID: uint32(support.ProgUnwindNative),
			name:   "unwind_native",
			enable: true,
		},
		{
			progID: uint32(support.ProgUnwindHotspot),
			name:   "unwind_hotspot",
			enable: cfg.IncludeTracers.Has(types.HotspotTracer),
		},
		{
			progID: uint32(support.ProgUnwindPerl),
			name:   "unwind_perl",
			enable: cfg.IncludeTracers.Has(types.PerlTracer),
		},
		{
			progID: uint32(support.ProgUnwindPHP),
			name:   "unwind_php",
			enable: cfg.IncludeTracers.Has(types.PHPTracer),
		},
		{
			progID: uint32(support.ProgUnwindPython),
			name:   "unwind_python",
			enable: cfg.IncludeTracers.Has(types.PythonTracer),
		},
		{
			progID: uint32(support.ProgUnwindRuby),
			name:   "unwind_ruby",
			enable: cfg.IncludeTracers.Has(types.RubyTracer),
		},
		{
			progID: uint32(support.ProgUnwindV8),
			name:   "unwind_v8",
			enable: cfg.IncludeTracers.Has(types.V8Tracer),
		},
		{
			progID: uint32(support.ProgUnwindDotnet),
			name:   "unwind_dotnet",
			enable: cfg.IncludeTracers.Has(types.DotnetTracer),
		},
	}
	if err = loadCustomKProbeUnwinders(coll, ebpfProgs, ebpfMaps["kprobe_progs"], tailCallProgs,
		cfg.BPFVerifierLogLevel, ebpfMaps["perf_progs"].FD()); err != nil {
		return nil, nil, fmt.Errorf("failed to load kprobe eBPF programs: %v", err)
	}

	if err = loadSystemConfig(coll, ebpfMaps, kernelSymbols, cfg.IncludeTracers,
		cfg.OffCPUThreshold, cfg.FilterErrorFrames); err != nil {
		return nil, nil, fmt.Errorf("failed to load system config: %v", err)
	}

	if err = removeTemporaryMaps(ebpfMaps); err != nil {
		return nil, nil, fmt.Errorf("failed to remove temporary maps: %v", err)
	}

	return ebpfMaps, ebpfProgs, nil
}

// loadCustomKProbeUnwinders reuses large parts of loadPerfUnwinders. By default all eBPF programs
// are written as perf event eBPF programs. loadKProbeUnwinders dynamically rewrites the
// specification of these programs to kprobe eBPF programs and adjusts tail call maps.
func loadCustomKProbeUnwinders(coll *cebpf.CollectionSpec, ebpfProgs map[string]*cebpf.Program,
	tailcallMap *cebpf.Map, tailCallProgs []progLoaderHelper,
	bpfVerifierLogLevel uint32, perfTailCallMapFD int) error {
	programOptions := cebpf.ProgramOptions{
		LogLevel: cebpf.LogLevel(bpfVerifierLogLevel),
	}

	progs := make([]progLoaderHelper, len(tailCallProgs)+2)
	copy(progs, tailCallProgs)
	progs = append(progs,
		progLoaderHelper{
			name:             "kprobe_collect_trace",
			noTailCallTarget: true,
			enable:           true,
		},
		progLoaderHelper{
			name:             "tp_process_exit",
			noTailCallTarget: true,
			enable:           true,
		},
	)
	for _, unwindProg := range progs {
		if !unwindProg.enable {
			continue
		}

		unwindProgName := unwindProg.name
		if !unwindProg.noTailCallTarget {
			unwindProgName = "kprobe_" + unwindProg.name
		}

		progSpec, ok := coll.Programs[unwindProgName]
		if !ok {
			return fmt.Errorf("program %s does not exist", unwindProgName)
		}

		// Replace the prog array for the tail calls.
		insns := progArrayReferences(perfTailCallMapFD, progSpec.Instructions)
		for _, ins := range insns {
			if err := progSpec.Instructions[ins].AssociateMap(tailcallMap); err != nil {
				return fmt.Errorf("failed to rewrite map ptr: %v", err)
			}
		}

		if err := loadProgram(ebpfProgs, tailcallMap, unwindProg.progID, progSpec,
			programOptions, unwindProg.noTailCallTarget); err != nil {
			return err
		}
	}

	return nil
}

// insertKernelFrames fetches the kernel stack frames for a particular kstackID and populates
// the trace with these kernel frames. It also allocates the memory for the frames of the trace.
// It returns the number of kernel frames for kstackID or an error.
func (t *CustomTracer) insertKernelFrames(trace *host.Trace, ustackLen uint32,
	kstackID int32) (uint32, error) {
	cKstackID := C.s32(kstackID)
	kstackVal := make([]C.uint64_t, support.PerfMaxStackDepth)

	if err := t.ebpfMaps["kernel_stackmap"].Lookup(unsafe.Pointer(&cKstackID),
		unsafe.Pointer(&kstackVal[0])); err != nil {
		return 0, fmt.Errorf("failed to lookup kernel frames for stackID %d: %v", kstackID, err)
	}

	// The kernel returns absolute addresses in kernel address
	// space format. Here just the stack length is needed.
	// But also debug print the symbolization based on kallsyms.
	var kstackLen uint32
	for kstackLen < support.PerfMaxStackDepth && kstackVal[kstackLen] != 0 {
		kstackLen++
	}

	trace.Frames = make([]host.Frame, kstackLen+ustackLen)

	var kernelSymbolCacheHit, kernelSymbolCacheMiss uint64

	for i := uint32(0); i < kstackLen; i++ {
		// Translate the kernel address into something that can be
		// later symbolized. The address is made relative to
		// matching module's ELF .text section:
		//  - main image should have .text section at start of the code segment
		//  - modules are ELF object files (.o) without program headers and
		//    LOAD segments. the address is relative to the .text section
		mod, addr, _ := t.kernelModules.LookupByAddress(
			libpf.SymbolValue(kstackVal[i]))

		fileID, foundFileID := t.moduleFileIDs[string(mod)]

		if !foundFileID {
			fileID = libpf.UnknownKernelFileID
		}

		hostFileID := host.FileIDFromLibpf(fileID)
		t.processManager.FileIDMapper.Set(hostFileID, fileID)

		trace.Frames[i] = host.Frame{
			File:   hostFileID,
			Lineno: libpf.AddressOrLineno(addr),
			Type:   libpf.KernelFrame,

			// For all kernel frames, the kernel unwinder will always produce a
			// frame in which the RIP is after a call instruction (it hides the
			// top frames that leads to the unwinder itself).
			ReturnAddress: true,
		}

		if !foundFileID {
			continue
		}

		// Kernel frame PCs need to be adjusted by -1. This duplicates logic done in the trace
		// converter. This should be fixed with PF-1042.
		frameID := libpf.NewFrameID(fileID, trace.Frames[i].Lineno-1)
		if t.reporter.FrameKnown(frameID) {
			kernelSymbolCacheHit++
			continue
		}
		kernelSymbolCacheMiss++

		if symbol, _, foundSymbol := t.kernelSymbols.LookupByAddress(
			libpf.SymbolValue(kstackVal[i])); foundSymbol {
			t.reporter.FrameMetadata(&reporter.FrameMetadataArgs{
				FrameID:      frameID,
				FunctionName: string(symbol),
			})
		}
	}

	t.fallbackSymbolMiss.Add(kernelSymbolCacheMiss)
	t.fallbackSymbolHit.Add(kernelSymbolCacheHit)

	return kstackLen, nil
}

// enableEvent removes the entry of given eventType from the inhibitEvents map
// so that the eBPF code will send the event again.
func (t *CustomTracer) enableEvent(eventType int) {
	inhibitEventsMap := t.ebpfMaps["inhibit_events"]

	// The map entry might not exist, so just ignore the potential error.
	et := uint32(eventType)
	_ = inhibitEventsMap.Delete(unsafe.Pointer(&et))
}

// loadBpfTrace parses a raw BPF trace into a `host.Trace` instance.
//
// If the raw trace contains a kernel stack ID, the kernel stack is also
// retrieved and inserted at the appropriate position.
func (t *CustomTracer) loadBpfTrace(raw []byte, cpu int) *host.Trace {
	frameListOffs := int(unsafe.Offsetof(C.Trace{}.frames))

	if len(raw) < frameListOffs {
		panic("trace record too small")
	}

	frameSize := int(unsafe.Sizeof(C.Frame{}))
	ptr := (*C.Trace)(unsafe.Pointer(unsafe.SliceData(raw)))

	// NOTE: can't do exact check here: kernel adds a few padding bytes to messages.
	if len(raw) < frameListOffs+int(ptr.stack_len)*frameSize {
		panic("unexpected record size")
	}

	pid := libpf.PID(ptr.pid)
	procMeta := t.processManager.MetaForPID(pid)
	trace := &host.Trace{
		Comm:             C.GoString((*C.char)(unsafe.Pointer(&ptr.comm))),
		ExecutablePath:   procMeta.Executable,
		ProcessName:      procMeta.Name,
		APMTraceID:       *(*libpf.APMTraceID)(unsafe.Pointer(&ptr.apm_trace_id)),
		APMTransactionID: *(*libpf.APMTransactionID)(unsafe.Pointer(&ptr.apm_transaction_id)),
		PID:              pid,
		TID:              libpf.PID(ptr.tid),
		Origin:           libpf.Origin(ptr.origin),
		OffTime:          int64(ptr.offtime),
		KTime:            times.KTime(ptr.ktime),
		CPU:              cpu,
	}

	if trace.Origin != support.TraceOriginSampling && trace.Origin != support.TraceOriginOffCPU {
		log.Warnf("Skip handling trace from unexpected %d origin", trace.Origin)
		return nil
	}

	// Trace fields included in the hash:
	//  - PID, kernel stack ID, length & frame array
	// Intentionally excluded:
	//  - ktime, COMM, APM trace, APM transaction ID, Origin and Off Time
	ptr.comm = [16]C.char{}
	ptr.apm_trace_id = C.ApmTraceID{}
	ptr.apm_transaction_id = C.ApmSpanID{}
	ptr.ktime = 0
	ptr.origin = 0
	ptr.offtime = 0
	trace.Hash = host.TraceHash(xxh3.Hash128(raw).Lo)

	userFrameOffs := 0
	if ptr.kernel_stack_id >= 0 {
		kstackLen, err := t.insertKernelFrames(
			trace, uint32(ptr.stack_len), int32(ptr.kernel_stack_id))

		if err != nil {
			log.Errorf("Failed to get kernel stack frames for 0x%x: %v", trace.Hash, err)
		} else {
			userFrameOffs = int(kstackLen)
		}
	}

	// If there are no kernel frames, or reading them failed, we are responsible
	// for allocating the columnar frame array.
	if len(trace.Frames) == 0 {
		trace.Frames = make([]host.Frame, ptr.stack_len)
	}

	for i := 0; i < int(ptr.stack_len); i++ {
		rawFrame := &ptr.frames[i]
		trace.Frames[userFrameOffs+i] = host.Frame{
			File:          host.FileID(rawFrame.file_id),
			Lineno:        libpf.AddressOrLineno(rawFrame.addr_or_line),
			Type:          libpf.FrameType(rawFrame.kind),
			ReturnAddress: rawFrame.return_address != 0,
		}
	}
	return trace
}

// StartOffCPUProfiling starts off-cpu profiling by attaching the programs to the hooks.
func (t *CustomTracer) StartOffCPUProfiling() error {
	// Attach the second hook for off-cpu profiling first.
	functionNames := []string{
		"__x64_sys_read",
		"__x64_sys_write",
		"__x64_sys_open",
		"__x64_sys_close",
	}
	kprobeProg, ok := t.ebpfProgs["kprobe_collect_trace"]
	if !ok {
		return errors.New("off-cpu program collect_traces is not available")
	}
	for _, functionName := range functionNames {
		kprobeSymbol, err := t.kernelSymbols.LookupSymbolByPrefix(functionName)
		if err != nil {
			return errors.New(fmt.Sprintf("failed to find kernel symbol for %s", functionName))
		}
		fmt.Printf("kprobe_symbol: %v\n", kprobeSymbol)
		kprobeLink, err := link.Kprobe(string(kprobeSymbol.Name), kprobeProg, nil)
		if err != nil {
			return err
		}
		t.hooks[hookPoint{group: "kprobe", name: functionName}] = kprobeLink
	}
	// Attach the first hook that enables off-cpu profiling.
	tpProg, ok := t.ebpfProgs["tp_process_exit"]
	if !ok {
		return errors.New("tp_process_exit is not available")
	}
	tpLink, err := link.Tracepoint("sched", "sched_process_exit", tpProg, nil)
	if err != nil {
		return nil
	}
	t.hooks[hookPoint{group: "sched", name: "sched_process_exit"}] = tpLink

	return nil
}

// TraceProcessor gets the trace processor.
func (t *CustomTracer) TraceProcessor() tracehandler.TraceProcessor {
	return t.processManager
}

func (t *CustomTracer) AddPidToTrack(pid int) {
	t.processManager.SynchronizeProcess(process.New(libpf.PID(pid)))
	pidMap, ok := t.ebpfMaps["pid_map"]
	if !ok {
		fmt.Printf("pid_map not found in ebpf maps")
		return
	}
	err := pidMap.Put(uint32(pid), uint32(pid))
	if err != nil {
		fmt.Printf("Failed to put pid %v into ebpf map: %v", pid, err)
		return
	}
	periodiccaller.Start(context.Background(), 10*time.Second, func() {
		t.processManager.SynchronizeProcess(process.New(libpf.PID(pid)))
	})
}

// startTraceEventMonitor spawns a goroutine that receives trace events from
// the kernel by periodically polling the underlying perf event buffer.
// Events written to the perf event buffer do not wake user-land immediately.
//
// Returns a function that can be called to retrieve perf event array
// error counts.
func (t *CustomTracer) StartTraceEventMonitor(ctx context.Context,
	traceOutChan chan<- *host.Trace) {
	eventsMap := t.ebpfMaps["trace_events"]
	eventReader, err := perf.NewReader(eventsMap,
		1024*int(unsafe.Sizeof(C.Trace{})))
	if err != nil {
		log.Fatalf("Failed to setup perf reporting via %s: %v", eventsMap, err)
	}

	// A deadline of zero is treated as "no deadline". A deadline in the past
	// means "always return immediately". We thus set a deadline 1 second after
	// unix epoch to always ensure the latter behavior.
	eventReader.SetDeadline(time.Unix(1, 0))

	var lostEventsCount, readErrorCount, noDataCount atomic.Uint64
	go func() {
		var data perf.Record
		var oldKTime, minKTime times.KTime

		pollTicker := time.NewTicker(t.intervals.TracePollInterval())
		defer pollTicker.Stop()

	PollLoop:
		for {
			select {
			case <-pollTicker.C:
				// Continue execution below.
			case <-ctx.Done():
				break PollLoop
			}

			minKTime = 0
			// Eagerly read events until the buffer is exhausted.
			for {
				if err = eventReader.ReadInto(&data); err != nil {
					if !errors.Is(err, os.ErrDeadlineExceeded) {
						readErrorCount.Add(1)
					}
					break
				}
				if data.LostSamples != 0 {
					lostEventsCount.Add(data.LostSamples)
					continue
				}
				if len(data.RawSample) == 0 {
					noDataCount.Add(1)
					continue
				}

				// Keep track of min KTime seen in this batch processing loop
				trace := t.loadBpfTrace(data.RawSample, data.CPU)
				if minKTime == 0 || trace.KTime < minKTime {
					minKTime = trace.KTime
				}
				traceOutChan <- trace
			}
			// After we've received and processed all trace events, call
			// ProcessedUntil if there is a pending oldKTime that we
			// haven't yet propagated to the rest of the agent.
			// This introduces both an upper bound to ProcessedUntil
			// call frequency (dictated by pollTicker) but also skips calls
			// when none are needed (e.g. no trace events have been read).
			//
			// We use oldKTime instead of minKTime (except when the latter is
			// smaller than the former) to take into account scheduling delays
			// that could in theory result in observed KTime going back in time.
			//
			// For example, as we don't control ordering of trace events being
			// written by the kernel in per-CPU buffers across CPU cores, it's
			// possible that given events generated on different cores with
			// timestamps t0 < t1 < t2 < t3, this poll loop reads [t3 t1 t2]
			// in a first iteration and [t0] in a second iteration. If we use
			// the current iteration minKTime we'll call
			// ProcessedUntil(t1) first and t0 next, with t0 < t1.
			if oldKTime > 0 {
				// Ensure that all previously sent trace events have been processed
				traceOutChan <- nil

				if minKTime > 0 && minKTime <= oldKTime {
					// If minKTime is smaller than oldKTime, use it and reset it
					// to avoid a repeat during next iteration.
					t.TraceProcessor().ProcessedUntil(minKTime)
					minKTime = 0
				} else {
					t.TraceProcessor().ProcessedUntil(oldKTime)
				}
			}
			oldKTime = minKTime
		}
	}()
}
