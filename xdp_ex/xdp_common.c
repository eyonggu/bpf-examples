#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <linux/if_link.h> /* XDP macros */

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

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

int xdp_link_detach(int ifindex, __u32 xdp_flags)
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

struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
	int first_prog_fd = -1;
	struct bpf_object *obj;
	int err;

	/* This struct allow us to set ifindex, this features is used for
	 * hardware offloading XDP programs (note this sets libbpf
	 * bpf_program->prog_ifindex and foreach bpf_map->map_ifindex).
	 */
	struct bpf_prog_load_attr prog_load_attr = {
		.prog_type = BPF_PROG_TYPE_XDP,
		.ifindex   = ifindex,
	};
	prog_load_attr.file = filename;

	/* Use libbpf for extracting BPF byte-code from BPF-ELF object, and
	 * loading this into the kernel via bpf-syscall
	 */
	err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
	if (err) {
		fprintf(stderr, "ERR: loading BPF-OBJ file(%s) (%d): %s\n",
			filename, err, strerror(-err));
		return NULL;
	}

	/* Notice how a pointer to a libbpf bpf_object is returned */
	return obj;
}

struct bpf_object *load_bpf_and_xdp_attach(char *filename, char *progsec,
					   int ifindex, int xdp_flags)
{
	struct bpf_program *bpf_prog;
	struct bpf_object *bpf_obj;
	int offload_ifindex = 0;
	int prog_fd = -1;
	int err;

	/* If flags indicate hardware offload, supply ifindex */
	if (xdp_flags & XDP_FLAGS_HW_MODE)
		offload_ifindex = ifindex;

	/* Load the BPF-ELF object file and get back libbpf bpf_object */
#if 0
	if (cfg->reuse_maps)
		bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename,
							  offload_ifindex,
							  cfg->pin_dir);
	else
#endif
		bpf_obj = load_bpf_object_file(filename, offload_ifindex);
	if (!bpf_obj) {
		fprintf(stderr, "ERR: loading file: %s\n", filename);
		exit(-1);
	}
	/* At this point: All XDP/BPF programs from the cfg->filename have been
	 * loaded into the kernel, and evaluated by the verifier. Only one of
	 * these gets attached to XDP hook, the others will get freed once this
	 * process exit.
	 */

	if (progsec)
		/* Find a matching BPF prog section name */
		bpf_prog = bpf_object__find_program_by_title(bpf_obj, progsec);
	else
		/* Find the first program */
		bpf_prog = bpf_program__next(NULL, bpf_obj);

	if (!bpf_prog) {
		fprintf(stderr, "ERR: couldn't find a program in ELF section '%s'\n", progsec);
		exit(-1);
	}

	prog_fd = bpf_program__fd(bpf_prog);
	if (prog_fd <= 0) {
		fprintf(stderr, "ERR: bpf_program__fd failed\n");
		exit(-1);
	}

	/* At this point: BPF-progs are (only) loaded by the kernel, and prog_fd
	 * is our select file-descriptor handle. Next step is attaching this FD
	 * to a kernel hook point, in this case XDP net_device link-level hook.
	 */
	err = xdp_link_attach(ifindex, xdp_flags, prog_fd);
	if (err)
		exit(err);

	printf("Sucess: Loaded BPF-object(%s) and used section(%s)\n",
		       filename, bpf_program__title(bpf_prog, false));
	printf(" - XDP prog attached on device(ifindx: %d)\n", ifindex);

	return bpf_obj;
}
