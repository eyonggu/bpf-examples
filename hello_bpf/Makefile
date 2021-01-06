CFLAGS=-DHAVE_ATTR_TEST=0

LLC ?= llc
CLANG ?= clang
#Now assume libbpf is compiled from github mirror and installed in STD INC (/usr/include/bpf)
#NOSTDINC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
LLC_FLAGS=

linuxhdrs ?=

BPFOBJS = hello_kern.o

COMMONOBJS = ../common/bpf_load.o
PROG = hello_user
OBJS = $(COMMONOBJS) $(PROG).o
LDLIBS = -l:libbpf.a -lelf -lz

.PHONY: all clean

all: $(BPFOBJS) $(PROG)

$(BPFOBJS): %.o:%.c
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -D__BPF_TRACING__ \
                -Wno-unused-value -Wno-pointer-sign \
                -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@

#Static Pattern Rules
$(OBJS): %.o:%.c
	$(CC) $(CFLAGS) -I../common -c $< -o $@

$(PROG): $(OBJS)
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(BPFOBJS) $(PROG)
