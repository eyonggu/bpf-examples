// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 2 of
// the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// Since this file was originally published in a blog post, a copy
// of the GNU General Public License version 2 was not included but
// can be found at
// https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "kp.h"

/* Deprecated by libbpf, use new BTF-defined to declare maps below.
struct bpf_map_def SEC("maps") sock_est = {
	.type = BPF_MAP_TYPE_LRU_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(struct timings),
	.max_entries = 1024,
};
*/

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__type(key, __u64);
	__type(value, struct timings);
	__uint(max_entries, 1024);
} sock_est SEC(".maps");

SEC("kprobe/tcp_connect")
int connect(struct pt_regs *ctx)
{
	int err;
	struct timings ts = {
		.t0 = bpf_ktime_get_ns(),
		.t1 = 0
	};
	struct sock *sk = (void*) PT_REGS_PARM1(ctx);
	// sk pointer
	__u64 skp;
	if ((err = bpf_probe_read(&skp, sizeof(__u64), &sk))) {
		char log[] = "bpf_probe_read %d\n";
		bpf_trace_printk(log, sizeof(log), err);
		return 1;
	}
	// note: map access is via the pointer to sock_est
	if ((err = bpf_map_update_elem(&sock_est, &skp, &ts, BPF_ANY))) {
		char log[] = "bpf_map_update_elem %d\n";
		bpf_trace_printk(log, sizeof(log), err);
		return 1;
	}
	return 0;
}

SEC("kprobe/tcp_finish_connect")
int finish_connect(struct pt_regs *ctx)
{
	int err;
	struct sock *sk = (void*) PT_REGS_PARM1(ctx);
	__u64 skp;
	if ((err = bpf_probe_read(&skp, sizeof(__u64), &sk))) {
		char log[] = "bpf_probe_read %d\n";
		bpf_trace_printk(log, sizeof(log), err);
		return 1;
	}
	struct timings* t = bpf_map_lookup_elem(&sock_est, &skp);
	if (t && t->t0) {
		t->t1 = bpf_ktime_get_ns();
		bpf_map_update_elem(&sock_est, &skp, t, BPF_ANY);
	}

	return 0;
}

char _license[] SEC("license") = "GPL";
