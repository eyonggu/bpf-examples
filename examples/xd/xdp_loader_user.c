/* SPDX-License-Identifier: GPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP macros */

#include <argp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "xdp_common_user.h"

struct arguments {
	char dev[16];
	char file[64];
	char progsec[64];
	bool do_unload;
	bool force_load;
	bool pin_maps;

	int ifindex;
	int xdp_flags;
};

/* Refer to https://www.gnu.org/software/libc/manual/html_node/Argp.html */
static struct argp_option options[] = {
	/* name    key   arg    flags   doc */
	{ "dev",   'd', "DEV",    0,    "Operate on device <ifname>" },
	{ "file",  'f', "FILE",   0,    "BPF object file to be loaded" },
	{ "progsec",'s', "PROGSEC",  0,    "Section to be loaded" },
	{ "pin",   'p',  0,       0,    "Mpas pinned under /sys/fs/bpf"},
	{ "unload",'u',  0,       0,    "Unload XDP program"},
	{ "force", 'F',  0,       0,    "Force loading, replacing existing"},
	{ 0 }
};
static char doc[] = "Simple prog to load/unload XDP eBPF prog";
static char args_doc[] = "...";
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	switch (key) {
	case 'd': strncpy(arguments->dev, arg, sizeof(arguments->dev)); break;
	case 'f': strncpy(arguments->file, arg, sizeof(arguments->file)); break;
	case 's': strncpy(arguments->progsec, arg, sizeof(arguments->progsec)); break;
	case 'p': arguments->pin_maps = true; break;
	case 'u': arguments->do_unload = true; break;
	case 'F': arguments->force_load = true; break;
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

int main(int argc, char **argv)
{
	struct arguments args;
	struct bpf_object *bpf_obj;
	struct bpf_prog_info info = {};
	__u32 info_len = sizeof(info);
	char *prog_sec = NULL;
	int prog_fd, err;

	memset(&args, 0, sizeof(args));
	strcpy(args.dev, "lo");  /* default 'lo" device */
	if (args.force_load)
		args.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

	argp_parse(&argp, argc, argv, 0, 0, &args);

	args.ifindex = if_nametoindex(args.dev);
	if (args.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		return -1;
	}

	if (args.do_unload)
		return xdp_link_detach(args.ifindex, args.xdp_flags);

#if 0
	/* Load the BPF-ELF object file and get back first BPF_prog FD */
	prog_fd = load_bpf_object_file__simple(args.file);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: loading file: %s\n", args.file);
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

#endif

	if (args.progsec[0])
		prog_sec = args.progsec;

	bpf_obj = load_bpf_and_xdp_attach(args.file, prog_sec, args.ifindex,
					  args.xdp_flags);
	if (!bpf_obj)
		return -1;

	if (args.pin_maps) {
		/* Use the --dev name as subdir for exporting/pinning maps */
		err = pin_maps_in_bpf_object(bpf_obj, args.dev);
		if (err) {
			fprintf(stderr, "ERR: pinning maps\n");
			return err;
		}
	}

	return 0;
}
