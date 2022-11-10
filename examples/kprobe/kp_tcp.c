// This program is free software: you can redistribute it and/or
// modify it under the terms of the GNU General Public License as
// published by the Free Software Foundation, either version 2 of
// the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
// Since this file was originally published in a blog post, a copy
// of the GNU General Public License version 2 was not included but
// can be found at
// https://www.gnu.org/licenses/old-licenses/gpl-2.0.html
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "kp.h"
#include "kp_tcp.skel.h"

static volatile sig_atomic_t stop;

static void sig_int(int signo)
{
	stop = 1;
}

int main(int argc, char const *argv[]) {
	// raise the rlimit or see
	// failed to create a map: 1 Operation not permitted
	// when load_bpf_file is run
	int ret;
	struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
	if ((ret = setrlimit(RLIMIT_MEMLOCK, &r))) {
		printf("setrlimit %d\n", ret);
		return ret;
	}

	struct kp_tcp_bpf *kp_tcp = kp_tcp_bpf__open_and_load();
	if (!kp_tcp) {
		printf("ERR: kp_tcp_bpf__open_and_load() failed\n");
		return -1;
	}

#if 0
	/* try some libbpf apis */

	/* here function name should be used as "name" parameter */
	struct bpf_program *bp = bpf_object__find_program_by_name(kp_tcp->obj, "connect");
	if (!bp)
		printf("Can't find connect program\n");

	if (!kp_tcp->progs.connect)
		printf("kp_tcp->progs.connect is NULL\n");

	printf("prog connect is %s autoloaded\n",
	       bpf_program__autoload(kp_tcp->progs.connect) ? "" : "NOT");

	printf("prog kp_tcp->progs.connect name: %s\n",
	       bpf_program__name(kp_tcp->progs.connect));
	printf("prog kp_tcp->progs.connect section name: %s\n",
	       bpf_program__section_name(kp_tcp->progs.connect));
#endif

	ret = kp_tcp_bpf__attach(kp_tcp);
	if (ret) {
		printf("ERR: kp_tcp_bpf__attach() failed\n");
		return ret;
	}

	while (!stop) {
		__u64 next_key = 0;
		__u64 key = 0;
		unsigned long long sum = 0;
		int total = 0;
		int err = 0;

		while (bpf_map__get_next_key(kp_tcp->maps.sock_est, &key,
					     &next_key, sizeof(key)) == 0) {
			struct timings t = {};
			if ((err = bpf_map__lookup_elem(kp_tcp->maps.sock_est,
							&next_key, sizeof(next_key),
							&t, sizeof(t), 0))) {
				printf("bpf_map_lookup_elem failed %d\n", err);
				break;
			}
			if (t.t1) {
				sum += t.t1 - t.t0;
				++total;
			}
			key = next_key;
		}
		if (sum) {
			printf("avg: %llu ns\n", sum/total);
		}
		sleep(2);
	}

	kp_tcp_bpf__destroy(kp_tcp);
	return 0;
}
