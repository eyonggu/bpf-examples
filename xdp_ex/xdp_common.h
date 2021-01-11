#ifndef __XDP_COMMON_H
#define __XDP_COMMON_H

#define XDP_UNKNOWN	XDP_REDIRECT + 1
#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_UNKNOWN + 1)
#endif

static const char *xdp_action_names[XDP_ACTION_MAX] = {
	[XDP_ABORTED]   = "XDP_ABORTED",
	[XDP_DROP]      = "XDP_DROP",
	[XDP_PASS]      = "XDP_PASS",
	[XDP_TX]        = "XDP_TX",
	[XDP_REDIRECT]  = "XDP_REDIRECT",
	[XDP_UNKNOWN]	= "XDP_UNKNOWN",
};

const char *action2str(__u32 action)
{
        if (action < XDP_ACTION_MAX)
                return xdp_action_names[action];
        return 0;
}

/* This is the data record stored in the map */
struct datarec {
	__u64 rx_packets;
	/* Assignment#1: Add byte counters */
};

int load_bpf_object_file__simple(const char *filename);

struct bpf_object *load_bpf_and_xdp_attach(char *filename, char *progsec,
					   int ifindex, int xdp_flags);

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd);
int xdp_link_detach(int ifindex, __u32 xdp_flags);

#endif
