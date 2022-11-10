#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#define SEC(NAME) __attribute__((section(NAME), used))


/* BPF programs only have limited support for function calls, helper functions
 * need to be inlined into the main function. The __always_inline marker on the
 * function definition ensures this, overriding any inlining decisions the
 * compiler would otherwise make.
 */
static __always_inline
int parse_ipv4(void *data, __u64 nh_off, void *data_end)
{
	struct iphdr *iph = data + nh_off;
	/* Note + 1 on pointer advance one iphdr struct size */
	if (iph + 1 > data_end) /* <-- Again verifier check our boundary checks */
		return 0;
	return iph->protocol;
}

SEC("xdp_drop_UDP") /* section in ELF-binary and "program_by_title" in libbpf */
int xdp_prog_drop_all_UDP(struct xdp_md *ctx) /* "name" visible with bpftool */
{
	void *data_end = (void *)(long)ctx->data_end; void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data; __u64 nh_off; __u32 ipproto = 0;
	nh_off = sizeof(*eth); /* ETH_HLEN == 14 */
	if (data + nh_off > data_end) /* <-- Verifier use this boundry check */
		return XDP_ABORTED;
	if (eth->h_proto == htons(ETH_P_IP))
		ipproto = parse_ipv4(data, nh_off, data_end);
	if (ipproto == IPPROTO_UDP)
		return XDP_DROP;
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";

