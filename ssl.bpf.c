#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define MAX_DATA_SIZE 256

struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};

struct event {
    __u32 pid;
    __u32 tid;
    __u32 len;
    char comm[16];
    char data[MAX_DATA_SIZE];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("uprobe/SSL_write")
int trace_ssl_write(struct user_pt_regs *ctx)
{
    struct event event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    const char *buf = (const char *)ctx->regs[1];
    int len = (int)ctx->regs[2];

    if (buf == 0 || len <= 0) {
        return 0;
    }

    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    event.len = len > MAX_DATA_SIZE ? MAX_DATA_SIZE : len;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_probe_read_user(event.data, event.len, buf);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
