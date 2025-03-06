#include "bpfdefs.h"
#include "frametypes.h"
#include "stackdeltatypes.h"
#include "tracemgmt.h"
#include "types.h"

bpf_map_def SEC("maps") pid_map = {
  .type        = BPF_MAP_TYPE_HASH,
  .key_size    = sizeof(u32),
  .value_size  = sizeof(u32),
  .max_entries = 1024,
};

SEC("kprobe/collect_trace")
int kprobe_collect_trace(struct bpf_perf_event_data *ctx)
{
  // Get the PID and TGID register.
  u64 id     = bpf_get_current_pid_tgid();
  u32 pid    = id >> 32;
  u32 tid    = id & 0xFFFFFFFF;
  u32 *exist = bpf_map_lookup_elem(&pid_map, &pid);
  if (exist == 0) {
    return 0;
  }
  printt("inside collect tracer %d", pid);
  u64 ts = bpf_ktime_get_ns();
  return collect_trace((struct pt_regs *)&ctx->regs, TRACE_OFF_CPU, pid, tid, ts, 0);
}

SEC("tracepoint/sched/sched_process_exit_new")
int tp_process_exit() {
  pid_t pid, tgid;
  u64 id = 0;

  /* get PID and TID of exiting thread/process */
  id = bpf_get_current_pid_tgid();
  pid = id >> 32;
  tgid = (u32)id;

  /* ignore thread exits */
  if (pid != tgid)
    return 0;
  bpf_map_delete_elem(&pid_map, &tgid);
  return 0;
}