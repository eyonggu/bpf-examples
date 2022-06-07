CLANG ?= clang
LLC ?= llc
LLC_FLAGS=
#NOSTDINC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
BPFTOOL=bpftool
EXTRA_CFLAGS=-I../include/

PROG=kp_tcp
OBJS=$(patsubst %.c,%.o,$(filter-out %.bpf.c,$(wildcard *.c)))
CFLAGS = -DHAVE_ATTR_TEST=0 -I./ -I../include/ -g
LDLIBS = -L ../lib -l:libbpf.a -lelf -lz

ifeq ($(V),1)
    Q=
else
    Q=@
endif

.PHONY: all clean

all: $(PROG)

%.bpf.o: %.bpf.c $(wildcard %.h)
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(NOSTDINC_FLAGS) $(LINUXINCLUDE) $(EXTRA_CFLAGS) \
		-D__KERNEL__ -D__BPF_TRACING__ \
                -Wno-unused-value -Wno-pointer-sign \
                -Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-Wno-unknown-warning-option $(CLANG_ARCH_ARGS) \
		-O2 -emit-llvm -c $< -o -| $(LLC) -march=bpf $(LLC_FLAGS) -filetype=obj -o $@


# Generate BPF skeletons
%.skel.h: %.bpf.o
	@echo "  BPFTOOL " $@
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OBJS): %.o:%.c %.skel.h
	@echo "  CC " $@
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(PROG): $(OBJS)
	@echo "  LINK " $@
	$(Q)$(CC) $^ -o $@ $(LDLIBS)

clean:
	@echo "  CLEAN "
	$(Q)rm -f $(PROG) $(OBJS) *.bpf.o *.skel.h

