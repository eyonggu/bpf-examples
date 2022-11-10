#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Comments from Linux Kernel:
 * Helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader.
 * End of comments

 * You can either use the helper header file below
 * so that you don't need to define it yourself:
 * #include <bpf/bpf_helpers.h>
 */
#define SEC(NAME) __attribute__((section(NAME), used))

SEC("xdp")
int xdp_drop_the_world(struct xdp_md *ctx) {
    // drop everything
    char fmt[] = "xdp_drop_the_world, ifindex=%u\n";
    bpf_trace_printk(fmt, sizeof(fmt), ctx->ingress_ifindex);
    return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
