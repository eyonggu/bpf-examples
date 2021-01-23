LLC ?= llc
CLANG ?= clang
#Now assume libbpf is compiled from github mirror and installed in STD INC (/usr/include/bpf)
#NOSTDINC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
LLC_FLAGS=

TOP = ..

KERNOBJS = $(patsubst %.c,%.o,$(wildcard *_kern.c))
USEROBJS = $(patsubst %.c,%.o,$(wildcard *_user.c))
COMMOBJS = xdp_common.o
PROGS = $(patsubst %_user.c,%,$(wildcard *_user.c))
LDLIBS = -l:libbpf.a -lelf

.PHONY: all clean

all: $(KERNOBJS) $(PROGS)

#static pattern rules for kern specific object
$(KERNOBJS): %.o:%.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -D__BPF_TRACING__ \
                -Wno-unused-value -Wno-pointer-sign \
                -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

#Pattern rules
%.o : %.c
	$(CC) $(CFLAGS) -c $< -o $@

xdp_loader: xdp_loader_user.o $(COMMOBJS)
	$(CC) $^ -o $@ $(LDLIBS)

xdp_stats: xdp_stats_user.o $(COMMOBJS)
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(KERNOBJS) $(COMMOBJS) $(USEROBJS) $(PROGS)
