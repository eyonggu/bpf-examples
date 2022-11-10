#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define SEC(NAME) __attribute__((section(NAME), used))

struct bpf_map_def SEC("maps") sock_map =
{
	.type = BPF_MAP_TYPE_SOCKMAP,
	.key_size = sizeof(int),
	.value_size = sizeof(int),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") proxy_map =
{
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned short),
	.value_size = sizeof(int),
	.max_entries = 2,
};

SEC("prog_parser")
int sockmap_parser(struct __sk_buff *skb)
{
	return skb->len;
}

SEC("prog_verdict")
int sockmap_verdict(struct __sk_buff *skb) {
	__u16 key = (__u16)bpf_ntohl(skb->remote_port);

	char info_fmt[] = "data to port [%d]\n";
	bpf_trace_printk(info_fmt, sizeof(info_fmt), key);

	int *idx = bpf_map_lookup_elem(&proxy_map, &key);
	if (!idx) {
		return SK_DROP;
	}

	return bpf_sk_redirect_map(skb, &sock_map, *idx, 0);
}

char _license[] SEC("license") = "GPL";
