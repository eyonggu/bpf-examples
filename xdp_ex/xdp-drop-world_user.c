/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "Simple XDP prog doing XDP_PASS\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <argp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */

struct arguments {
	char dev[16];
	char bpf[64];
	bool do_unload;

	int ifindex;
	int xdp_flags;
};

/* Refer to https://www.gnu.org/software/libc/manual/html_node/Argp.html */
static struct argp_option options[] = {
	/* name    key   arg    flags   doc */
	{ "dev",   'd', "DEV",    0,    "Operate on device <ifname>" },
	{ "file",  'f', "FILE",   0,    "BPF object file to be loaded" },
	{ "unload",'u',  0,       0,    "Unload XDP program"},
	{ 0 }
};
static char doc[] = "Simple XDP prog";
static char args_doc[] = "...";
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	switch (key) {
	case 'd': strncpy(arguments->dev, arg, 16); break;
	case 'f': strncpy(arguments->bpf, arg, 16); break;
	case 'u': arguments->do_unload = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}

	return 0;
}
static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

#if 0
static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{0, 0, NULL,  0 }, NULL, false}
};
#endif

int load_bpf_object_file__simple(const char *filename)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.file = filename,
	};


	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return -1;
	}

	/* Simply return the first program file descriptor.
	 * (Hint: This will get more advanced later)
	 */
	return first_prog_fd;
}

static int xdp_link_detach(int ifindex, __u32 xdp_flags)
{
	int err;

	if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0) {
		fprintf(stderr, "ERR: link set xdp unload failed (err=%d):%s\n",
			err, strerror(-err));
		return err;
	}
	return 0;
}

int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
	int err;

	/* libbpf provide the XDP net_device link-level hook attach helper */
	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST)) {
		/* Force mode didn't work, probably because a program of the
		 * opposite type is loaded. Let's unload that and try loading
		 * again.
		 */

		__u32 old_flags = xdp_flags;

		xdp_flags &= ~XDP_FLAGS_MODES;
		xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ?
			XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
		err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
		if (!err)
			err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
	}

	if (err < 0) {
		fprintf(stderr, "ERR: "
			"ifindex(%d) link set xdp fd failed (%d): %s\n",
			ifindex, -err, strerror(-err));

		switch (-err) {
		case EBUSY:
		case EEXIST:
			fprintf(stderr, "Hint: XDP already loaded on device"
				" use --force to swap/replace\n");
			break;
		case EOPNOTSUPP:
			fprintf(stderr, "Hint: Native-XDP not supported"
				" use --skb-mode or --auto-mode\n");
			break;
		default:
			break;
		}
		return err;
	}

	return 0;
}

int main(int argc, char **argv)
{
	struct arguments args;

	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	int prog_fd, err;

#if 0
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};
#endif
	strcpy(args.dev, "lo");  /* default 'lo" device */
	args.xdp_flags = 0;
	args.do_unload = false;

	argp_parse(&argp, argc, argv, 0, 0, &args);

	args.ifindex = if_nametoindex(args.dev);
	if (args.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		return -1;
	}

	if (args.do_unload)
		return xdp_link_detach(args.ifindex, args.xdp_flags);

	/* Load the BPF-ELF object file and get back first BPF_prog FD */
	prog_fd = load_bpf_object_file__simple(args.bpf);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: loading file: %s\n", args.bpf);
		return -1;
	}

	/* At this point: BPF-prog is (only) loaded by the kernel, and prog_fd
	 * is our file-descriptor handle. Next step is attaching this FD to a
	 * kernel hook point, in this case XDP net_device link-level hook.
	 * Fortunately libbpf have a helper for this:
	 */
	err = xdp_link_attach(args.ifindex, args.xdp_flags, prog_fd);
	if (err)
		return err;

        /* This step is not really needed , BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: can't get prog info - %s\n",
			strerror(errno));
		return err;
	}

	printf("Success: Loading "
	       "XDP prog name:%s(id:%d) on device:%s(ifindex:%d)\n",
	       info.name, info.id, args.dev, args.ifindex);

	return 0;
}
