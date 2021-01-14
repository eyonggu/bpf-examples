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
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf_load.h>
#include "kp.h"

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
	if (load_bpf_file("kp_tcp_kern.o")) {
		printf("%s\n", bpf_log_buf);
		return 1;
	}
	while (1) {
		__u64 next_key = 0;
		__u64 key = 0;
		unsigned long long sum = 0;
		int total = 0;
		int err = 0;
		while (bpf_map_get_next_key(map_fd[0], &key, &next_key) == 0) {
			struct timings t = {};
			if ((err = bpf_map_lookup_elem(map_fd[0], &next_key, &t))) {
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
	return 0;
}
