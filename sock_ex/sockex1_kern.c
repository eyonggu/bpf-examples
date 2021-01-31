/* copied sample from kernel tree */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include "bpf/bpf_legacy.h"

/* not working with this definition, don't know why...
 * error when loading:
 *    libbpf: elf: skipping unrecognized data section(7) .eh_frame
 *    libbpf: elf: skipping relo section(8) .rel.eh_frame for section(7) .eh_frame
 *    libbpf: BTF is required, but is missing or corrupted.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, long);
	__uint(max_entries, 256);
} my_map SEC(".maps");
*/

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(long),
	.max_entries = 256,
};

SEC("socket1")
int bpf_prog1(struct __sk_buff *skb)
{
	int index = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
	long *value;
#if 0
	char fmt[] = "skb->pkt_type: %u\n";
	bpf_trace_printk(fmt, sizeof(fmt), skb->pkt_type);
#endif

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len);

	return 0;
}

char _license[] SEC("license") = "GPL";
