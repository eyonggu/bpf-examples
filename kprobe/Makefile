LLC ?= llc
CLANG ?= clang
NOSTDINC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
LLC_FLAGS=

LINUXINCLUDE = -I/usr/src/linux-source-5.4.0/usr/include
LINUXINCLUDE += -I/usr/src/linux-source-5.4.0/tools/testing/selftests/

KERNOBJS = $(patsubst %.c,%.o,$(wildcard *_kern.c))
PROGS = $(patsubst %_user.c,%,$(wildcard *_user.c))
OBJS = $(patsubst %.c,%.o,$(wildcard *_user.c))
COMOBJS += ../common/bpf_load.o
CFLAGS = -DHAVE_ATTR_TEST=0
LDLIBS = ../lib/libbpf.a -lelf

.PHONY: all clean

all: $(KERNOBJS) $(PROGS)

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

$(COMOBJS): %.o:%.c
	$(CC) $(CFLAGS) -I../include -c $< -o $@

#Static Pattern Rules
$(OBJS): %.o:%.c
	$(CC) $(CFLAGS) -I../common -c $< -o $@

kp_tcp: kp_tcp_user.o $(COMOBJS)
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(KERNOBJS) $(OBJS) $(COMOBJS) $(PROGS)
