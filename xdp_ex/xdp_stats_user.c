#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <locale.h>
#include <unistd.h>
#include <time.h>

#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h> /* XDP macros */

#include <argp.h>

#include "xdp_common.h"
#include "common_kern_user.h"

struct arguments {
	char dev[16];
	char bpf[64];
	char progsec[64];
	bool force_load;
	bool skip_load;

	int ifindex;
	int xdp_flags;
};

/* Refer to https://www.gnu.org/software/libc/manual/html_node/Argp.html */
static struct argp_option options[] = {
	/* name    key   arg    flags   doc */
	{ "dev",   'd', "DEV",    0,    "Operate on device <ifname>" },
	{ "file",  'f', "FILE",   0,    "BPF object file to be loaded" },
	{ "progsec",'p', "PROG",  0,    "Section to be used" },
	{ "skip",  's',  0,       0,    "Skip XDP program loading"},
	{ "force", 'F',  0,       0,    "Force loading, replacing existing"},
	{ 0 }
};
static char doc[] = "Simple XDP prog";
static char args_doc[] = "...";
static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
	struct arguments *arguments = state->input;
	switch (key) {
	case 'd': strncpy(arguments->dev, arg, sizeof(arguments->dev)); break;
	case 'f': strncpy(arguments->bpf, arg, sizeof(arguments->bpf)); break;
	case 'p': strncpy(arguments->progsec, arg, sizeof(arguments->progsec)); break;
	case 's': arguments->skip_load = true; break;
	case 'F': arguments->force_load = true; break;
	default: return ARGP_ERR_UNKNOWN;
	}

	return 0;
}
static struct argp argp = { options, parse_opt, args_doc, doc, 0, 0, 0 };

struct record {
	__u64 timestamp;
	struct datarec total;
};

struct stats_record {
	struct record stats[1]; /* Assignment#2: Hint */
};

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(res);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}

/* BPF_MAP_TYPE_ARRAY */
void map_get_value_array(int fd, __u32 key, struct datarec *value)
{
	if ((bpf_map_lookup_elem(fd, &key, value)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = libbpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}

	/* Sum values from each CPU */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
}

static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;

	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();

	switch (map_type) {
	case BPF_MAP_TYPE_ARRAY:
		map_get_value_array(fd, key, &value);
		break;
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}

	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes = value.rx_bytes;
	return true;
}

static void stats_collect(int map_fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	/* Assignment#2: Collect other XDP actions stats  */
	__u32 key = XDP_PASS;

	map_collect(map_fd, map_type, key, &stats_rec->stats[0]);
}

static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	double period;
	__u64 packets, kbytes;
	double pps; /* packets per sec */
	double mbps; /* mbits per sec */

	/* Assignment#2: Print other XDP actions stats  */
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		const char *action = action2str(XDP_PASS);
		rec  = &stats_rec->stats[0];
		prev = &stats_prev->stats[0];

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps     = packets / period;

		kbytes = (rec->total.rx_bytes - prev->total.rx_bytes) / 1000;
		mbps = (kbytes * 8) / (1000 * period);


		printf(fmt, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes, mbps, period);
	}
}

static void stats_poll(int map_fd, __u32 map_type, int interval)
{
	struct stats_record prev, record = { 0 };

	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");

	/* Print stats "header" */
	if (1) {
		printf("\n");
		printf("%-12s\n", "XDP-action");
	}

	/* Get initial reading quickly */
	stats_collect(map_fd, map_type, &record);
	usleep(1000000/4);

	while (1) {
		prev = record; /* struct copy */
		stats_collect(map_fd, map_type, &record);
		stats_print(&record, &prev);
		sleep(interval);
	}
}

int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;

	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}

	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

int main(int argc, char **argv)
{
	struct arguments args;
	struct bpf_object *bpf_obj;
	int stats_map_fd;
	struct bpf_map_info map_info;
	__u32 map_info_size = sizeof(map_info);
	int interval = 2;
	int len, err;

	/* parse options */
	strcpy(args.dev, "lo");  /* default 'lo" device */
	args.xdp_flags = 0;
	if (args.force_load)
		args.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE;
	strcpy(args.progsec, "xdp_stats1");

	argp_parse(&argp, argc, argv, 0, 0, &args);

	args.ifindex = if_nametoindex(args.dev);
	if (args.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		return -1;
	}

	if (args.skip_load) {
		/* Use the --dev name as subdir for finding pinned maps */
		stats_map_fd = open_bpf_map_file(args.dev, "xdp_stats_map",
						 &map_info);
		if (stats_map_fd < 0) {
			return -1;
		}

		stats_poll(stats_map_fd, map_info.type, interval);

		return 0;
	}

	bpf_obj = load_bpf_and_xdp_attach(args.bpf, NULL, args.ifindex,
					  args.xdp_flags);
	if (!bpf_obj)
		return -1;

	stats_map_fd = find_map_fd(bpf_obj, "xdp_stats_map");
	if (stats_map_fd < 0) {
		xdp_link_detach(args.ifindex, args.xdp_flags);
		return -1;
	}

	err = bpf_obj_get_info_by_fd(stats_map_fd, &map_info,
				     &map_info_size);
	if (err) {
		fprintf(stderr, "ERR: can't get map(%s) info - %s\n",
			"xdp_stats_map", strerror(errno));
		return err;
	} else {
		printf("Map: key_size=%d, value_size=%d, max_entries=%d, type=%u\n",
		       map_info.key_size, map_info.value_size, map_info.max_entries, map_info.type);
	}

	stats_poll(stats_map_fd, map_info.type, interval);

	return 0;
}
