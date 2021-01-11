#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	/* Assignment#1: Add byte counters */
};

/* Creating a BPF map is done by defining a global struct bpf_map_def,
 * with a special SEC("maps") as below */
struct bpf_map_def SEC("maps") xdp_stats_map = {
	.type        = BPF_MAP_TYPE_ARRAY,
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
	// void *data_end = (void *)(long)ctx->data_end;
	// void *data     = (void *)(long)ctx->data;
	struct datarec *rec;
	__u32 key = XDP_PASS; /* XDP_PASS = 2 */

	/* Lookup in kernel BPF-side return pointer to actual data record */
	rec = bpf_map_lookup_elem(&xdp_stats_map, &key);
	/* BPF kernel-side verifier will reject program if the NULL pointer
	 * check isn't performed here. Even-though this is a static array where
	 * we know key lookup XDP_PASS always will succeed.
	 */
	if (!rec)
		return XDP_ABORTED;

	/* Multiple CPUs can access data record. Thus, the accounting needs to
	 * use an atomic operation.
	 */
	lock_xadd(&rec->rx_packets, 1);
        /* Assignment#1: Add byte counters
         * - Hint look at struct xdp_md *ctx (copied below)
         *
         * Assignment#3: Avoid the atomic operation
         * - Hint there is a map type named BPF_MAP_TYPE_PERCPU_ARRAY
         */

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
