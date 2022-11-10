#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "xdp_common_kern_user.h"

/* Creating a BPF map is done by defining a global struct bpf_map_def,
 * with a special SEC("maps") as below */
struct bpf_map_def SEC("maps") xdp_stats_map = {
	//.type        = BPF_MAP_TYPE_ARRAY,
	.type        = BPF_MAP_TYPE_PERCPU_ARRAY,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(struct datarec),
	.max_entries = XDP_ACTION_MAX,
};

/* LLVM maps __sync_fetch_and_add() as a built-in function to the BPF atomic add
 * instruction (that is BPF_STX | BPF_XADD | BPF_W for word sizes)
 */
#ifndef lock_xadd
#define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
#endif

SEC("xdp_stats1")
int  xdp_stats1_func(struct xdp_md *ctx)
{
	/* Note, __u32 in struct xdp_md is not actually their real data types,
	 * as access to this data-structure is remapped by the kernel when the
	 * program is loaded into the kernel. Access gets remapped to
	 * struct xdp_buff and also struct xdp_rxq_info */
	void *data_end = (void *)(long)ctx->data_end;
	void *data     = (void *)(long)ctx->data;
	__u64 bytes = data_end - data;
	struct datarec *rec;
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

	/* Lookup in kernel BPF-side return pointer to actual data record */
	/* EYONGGU: don't be confused by bpf_map_lookup_elem() from libbpf, here
	 * is the helper function */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
		return XDP_ABORTED;

	/*
	 * When using BPF_MAP_TYPE_ARRAY, multiple CPUs can access data record.
	 * Thus, the accounting needs to use an atomic operation.
	 */
	//lock_xadd(&rec->rx_packets, 1);
	//lock_xadd(&rec->rx_bytes, bytes);
	rec->rx_packets += 1;
	rec->rx_bytes += bytes;

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
