#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include "bpf_load.h"

#ifdef USE_BPFTOOL_SKEL
#include "hello_kern_skel.h"
#endif

static void read_trace_pipe(void)
{
	int trace_fd;

	trace_fd = open(DEBUGFS "trace_pipe", O_RDONLY, 0);
	if (trace_fd < 0)
		return;

	while (1) {
		static char buf[4096];
		ssize_t sz;

		sz = read(trace_fd, buf, sizeof(buf) - 1);
		if (sz > 0) {
			buf[sz] = 0;
			puts(buf);
		}
	}
}

int main(int argc, char **argv)
{
#ifdef USE_BPFTOOL_SKEL
	hello_kern__open_and_load();
#else
	if (load_bpf_file("hello_kern.o") != 0) {
		printf("The kernel didn't load BPF program\n");
		return -1;
	}
#endif

	read_trace_pipe();
	return 0;
}
