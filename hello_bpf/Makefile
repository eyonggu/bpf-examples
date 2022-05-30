
CLANG ?= clang
LLC ?= llc
#Now assume libbpf is compiled from github mirror and installed in STD INC (/usr/include/bpf)
#NOSTDINC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
LLC_FLAGS=
BPFTOOL=bpftool



BPFOBJ=hello_kern.o
BPFSKEL=hello_kern_skel.h
PROG=hello_user
USEROBJS=hello_user.o bpf_load/bpf_load.o
CFLAGS=-DHAVE_ATTR_TEST=0 -I./ -I../include -I./bpf_load -I./bpf_load/include
ifdef USE_BPFTOOL_SKEL
CFLAGS+=-DUSE_BPFTOOL_SKEL
endif
LDLIBS = -L ../lib -l:libbpf.a -lelf -lz

ifeq ($(V),1)
    Q=
else
    Q=@
endif

.PHONY: all clean

all: $(BPFOBJ) $(PROG)

$(BPFOBJ): %.o:%.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -D__BPF_TRACING__ \
                -Wno-unused-value -Wno-pointer-sign \
                -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@


ifdef USE_BPFTOOL_SKEL
$(BPFSKEL): $(BPFOBJ)
	@echo "  BPFTOOL " $@
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(USEROBJS): %.o:%.c $(BPFSKEL)
	@echo "  CC " $@
	$(Q)$(CC) $(CFLAGS) -c $< -o $@
else
#Static Pattern Rules
$(USEROBJS): %.o:%.c
	@echo "  CC " $@
	$(Q)$(CC) $(CFLAGS) -c $< -o $@
endif

$(PROG): $(USEROBJS)
	@echo "  LINK " $@
	$(Q)$(CC) $^ -o $@ $(LDLIBS)

clean:
	@echo "  CLEAN "
	$(Q)rm -f $(BPFOBJ) $(USEROBJS) $(BPFSKEL) $(PROG)
