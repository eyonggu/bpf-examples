LLC ?= llc
CLANG ?= clang
NOSTDINC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
LLC_FLAGS=

LINUXINCLUDE ?= -I../common/include
LINUXINCLUDE += -I/usr/src/linux-headers-5.4.0-58/include

KERNOBJS = $(patsubst %.c,%.o,$(wildcard *_kern.c))
PROGS = $(patsubst %_user.c,%,$(wildcard *_user.c))
USEROBJS = $(patsubst %.c,%.o,$(wildcard *_user.c))
CFLAGS = -DHAVE_ATTR_TEST=0 -I../common/include
LDLIBS = ../common/lib/libbpf.a -lelf

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

#Static Pattern Rules
$(USEROBJS): %.o:%.c
	$(CC) $(CFLAGS) -I. -I../common -c $< -o $@

sockex1: sockex1_user.o
	$(CC) $^ -o $@ $(LDLIBS)

clean:
	rm -f $(KERNOBJS) $(USEROBJS) $(PROGS)
