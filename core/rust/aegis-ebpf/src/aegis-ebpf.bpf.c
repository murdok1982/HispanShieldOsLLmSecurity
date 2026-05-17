// SPDX-License-Identifier: GPL-2.0
// aegis-ebpf.bpf.c — HispanShield OS kernel-side eBPF probes (Fase 2)
//
// Compile with:
//   clang -O2 -g -target bpf \
//     -I/usr/include/x86_64-linux-gnu \
//     -c aegis-ebpf.bpf.c -o aegis-ebpf.bpf.o
//
// Probes:
//   1. tracepoint/syscalls/sys_enter_execve  — capture every exec
//   2. kprobe/do_init_module                 — detect unsigned module loads
//   3. tracepoint/syscalls/sys_enter_prctl   — detect capability manipulation

#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ── Shared event structure (must match SyscallEvent in main.rs) ──────────────

#define COMM_LEN 16
#define PATH_LEN 128
#define EVENT_EXEC   1
#define EVENT_KMOD   2
#define EVENT_PRCTL  3

struct aegis_event {
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u32 event_type;
    __u64 timestamp_ns;
    __u8  suspicious;
    __u8  comm[COMM_LEN];
    __u8  path[PATH_LEN];
};

// Perf ring buffer — userspace reads via AyaPerfEventArray
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} SYSCALL_EVENTS SEC(".maps");

// PID blocklist map (filled by userspace for known-malicious PIDs)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u8));
    __uint(max_entries, 256);
} pid_blocklist SEC(".maps");

// ── Helpers ──────────────────────────────────────────────────────────────────

static __always_inline __u32 get_ppid(void)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent;
    __u32 ppid = 0;
    bpf_core_read(&parent, sizeof(parent), &task->real_parent);
    bpf_core_read(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

// High-risk process names that should never exec as root
static __always_inline __u8 is_suspicious_exec(const __u8 *comm)
{
    // netcat variants
    if (comm[0]=='n' && comm[1]=='c' && (comm[2]==0 || comm[2]=='.'))
        return 1;
    // bash spawned outside operator session
    if (comm[0]=='b' && comm[1]=='a' && comm[2]=='s' && comm[3]=='h' && comm[4]==0)
        return 1;
    // curl / wget unexpected outbound
    if (comm[0]=='c' && comm[1]=='u' && comm[2]=='r' && comm[3]=='l' && comm[4]==0)
        return 1;
    if (comm[0]=='w' && comm[1]=='g' && comm[2]=='e' && comm[3]=='t' && comm[4]==0)
        return 1;
    return 0;
}

// ── Probe 1: sys_enter_execve ────────────────────────────────────────────────

// Tracepoint format: /sys/kernel/debug/tracing/events/syscalls/sys_enter_execve/format
struct execve_args {
    __u64 __unused;       // common fields
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct execve_args *ctx)
{
    struct aegis_event ev = {};

    ev.event_type   = EVENT_EXEC;
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid          = bpf_get_current_pid_tgid() >> 32;
    ev.uid          = bpf_get_current_uid_gid() & 0xffffffff;
    ev.ppid         = get_ppid();
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    bpf_probe_read_user_str(ev.path, sizeof(ev.path), ctx->filename);

    // Flag as suspicious: root uid + known-dangerous comm
    if (ev.uid == 0 && is_suspicious_exec(ev.comm))
        ev.suspicious = 1;

    // Also flag PIDs in the blocklist
    __u8 *blocked = bpf_map_lookup_elem(&pid_blocklist, &ev.pid);
    if (blocked)
        ev.suspicious = 1;

    bpf_perf_event_output(ctx, &SYSCALL_EVENTS, BPF_F_CURRENT_CPU,
                          &ev, sizeof(ev));
    return 0;
}

// ── Probe 2: do_init_module (unsigned kernel module detection) ───────────────

SEC("kprobe/do_init_module")
int detect_unsigned_kmod(struct pt_regs *ctx)
{
    struct aegis_event ev = {};

    ev.event_type   = EVENT_KMOD;
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid          = bpf_get_current_pid_tgid() >> 32;
    ev.uid          = bpf_get_current_uid_gid() & 0xffffffff;
    ev.ppid         = get_ppid();
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));

    // Any kernel module loaded outside of boot is suspicious in a locked-down system
    ev.suspicious = 1;

    bpf_perf_event_output(ctx, &SYSCALL_EVENTS, BPF_F_CURRENT_CPU,
                          &ev, sizeof(ev));
    return 0;
}

// ── Probe 3: sys_enter_prctl (capability / process attribute manipulation) ───

struct prctl_args {
    __u64 __unused;
    int option;
    unsigned long arg2;
    unsigned long arg3;
    unsigned long arg4;
    unsigned long arg5;
};

// PR_SET_DUMPABLE=4, PR_SET_SECCOMP=22, PR_CAP_AMBIENT=47
#define PR_SET_SECCOMP  22
#define PR_CAP_AMBIENT  47

SEC("tracepoint/syscalls/sys_enter_prctl")
int trace_prctl(struct prctl_args *ctx)
{
    // Only alert on security-relevant prctl options
    if (ctx->option != PR_SET_SECCOMP && ctx->option != PR_CAP_AMBIENT)
        return 0;

    struct aegis_event ev = {};
    ev.event_type   = EVENT_PRCTL;
    ev.timestamp_ns = bpf_ktime_get_ns();
    ev.pid          = bpf_get_current_pid_tgid() >> 32;
    ev.uid          = bpf_get_current_uid_gid() & 0xffffffff;
    ev.ppid         = get_ppid();
    bpf_get_current_comm(ev.comm, sizeof(ev.comm));
    ev.suspicious   = 1;

    bpf_perf_event_output(ctx, &SYSCALL_EVENTS, BPF_F_CURRENT_CPU,
                          &ev, sizeof(ev));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
