bpf_load.[ch] are copied from kernel source tree, which loads bpf object file and attach to hooks based on the program section name. <br/>
(This loader utility has removed from the kernel tree since v5.11, instead of using skeleton generated by "bpftool gen")

To compile it, following files are copid from kernel source tree as well:

- bpf_load.[ch] -> samples/bpf/bpf_load.[ch]
- bpf/bpf.h -> tools/lib/bpf/bpf.h
- bpf/libbpf.h -> tools/lib/bpf/libbpf.h
- bpf/bpf_helpers.h -> tools/testing/selftests/bpf/bpf_helpers.h
- perf-sys.h -> tools/perf/perf-sys.h
- linux/types.h -> tools/include/linux/types.h
- linux/compiler.h -> tools/include/linux/compiler.h
- linux/compiler-gcc.h -> tools/include/linux/compiler-gcc.h


NOTE, there could be multiple bpf.h installed:
- /usr/include/bpf/bpf.h -> tools/lib/bpf/bpf.h (from libbpf)
- /usr/include/linux/bpf.h -> include/uapi/linux/bpf.h  (primitive bpf header for user program)
