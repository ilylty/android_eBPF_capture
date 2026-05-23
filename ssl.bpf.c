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
    __u32 direction;
    char comm[16];
    char data[MAX_DATA_SIZE];
};

struct read_args {
    const char *buf;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct read_args);
} active_reads SEC(".maps");

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
    event.direction = 0;
    if (len > MAX_DATA_SIZE) {
        len = MAX_DATA_SIZE;
    }
    event.len = (__u32)len;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_probe_read_user(event.data, MAX_DATA_SIZE, buf);

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

SEC("uprobe/SSL_read")
int trace_ssl_read_enter(struct user_pt_regs *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args args = {};

    args.buf = (const char *)ctx->regs[1];
    if (args.buf != 0) {
        bpf_map_update_elem(&active_reads, &pid_tgid, &args, BPF_ANY);
    }
    return 0;
}

SEC("uretprobe/SSL_read")
int trace_ssl_read_exit(struct user_pt_regs *ctx)
{
    struct event event = {};
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct read_args *args = bpf_map_lookup_elem(&active_reads, &pid_tgid);
    int len = (int)ctx->regs[0];

    if (args == 0 || args->buf == 0 || len <= 0) {
        bpf_map_delete_elem(&active_reads, &pid_tgid);
        return 0;
    }

    event.pid = pid_tgid >> 32;
    event.tid = (__u32)pid_tgid;
    event.direction = 1;
    if (len > MAX_DATA_SIZE) {
        len = MAX_DATA_SIZE;
    }
    event.len = (__u32)len;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    bpf_probe_read_user(event.data, MAX_DATA_SIZE, args->buf);
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    bpf_map_delete_elem(&active_reads, &pid_tgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
