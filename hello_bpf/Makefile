LLC ?= llc
CLANG ?= clang

LLC_FLAGS=

.PHONY: all clean

all: hello_bpf hello_kern.o

hello_kern.o: hello_kern.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -D__BPF_TRACING__ \
                -Wno-unused-value -Wno-pointer-sign \
                -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

hello_bpf: bpf_load.o hello_user.o
	$(CC) $^ -o $@ /usr/lib64/libbpf.a -lelf -lz

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o hello_bpf
