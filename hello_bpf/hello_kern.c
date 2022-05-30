#include <linux/bpf.h>
/* #include <bpf/bpf_helpers.h> */
#include "../libbpf/src/bpf_helpers.h"

SEC("tracepoint/syscalls/sys_enter_execve")
int bpf_prog(void *ctx)
{
	char msg[] = "Hello BPF!\n";

	/* print message to /sys/kernel/debug/tracing/trace */
	bpf_trace_printk(msg, sizeof(msg));

	return 0;
}

char _license[] SEC("license") = "GPL";
