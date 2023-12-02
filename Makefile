ifeq ($(V),1)
  Q =
else
  Q = @
endif

ifeq ($(TOPDIR),)
TOPDIR := $(shell pwd)
endif

.PHONY: all clean test
all: $(PROG)

_OUTPUT := $(TOPDIR)/.output

#Common
ARCH := x86
CLANG ?= clang
CLANG_BPF_INCLUDES=-I$(TOPDIR)/usr/include -I$(TOPDIR)/vmlinux/

CFLAGS = -I./ -I$(TOPDIR)/usr/include/ -g
LDLIBS = -L$(TOPDIR)/usr/lib64 -l:libbpf.a -lelf -lz

#LIBBPF
LIBBPF_SRC = $(TOPDIR)/libbpf/src
LIBBPF_OUTPUT := $(_OUTPUT)/libbpf
LIBBPF := $(LIBBPF_OUTPUT)/libbpf.a

$(LIBBPF_OUTPUT):
	$(QUIET_MKDIR)mkdir -p $@

$(LIBBPF): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(LIBBPF_OUTPUT)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) OBJDIR=$(patsubst %/,%,$(LIBBPF_OUTPUT)) BUILD_STATIC_ONLY=y
	#$(Q)$(MAKE) -C $(LIBBPF_SRC) PREFIX=$(TOPDIR) BUILD_STATIC_ONLY=y install
	$(Q)$(MAKE) -C $(LIBBPF_SRC) DESTDIR=$(TOPDIR) BUILD_STATIC_ONLY=y install

#BPFTOOL
#BPFTOOL=$(TOPDIR)/bin/bpftool
BPFTOOL=bpftool

%.bpf.o: %.bpf.c $(wildcard %.h)
	@echo "  CLANG-bpf " $@
	$(Q)$(CLANG) $(CLANG_BPF_INCLUDES) -D__TARGET_ARCH_$(ARCH) -g -O2 -target bpf -c $< -o $@

# Generate BPF skeletons
%.skel.h: %.bpf.o
	@echo "  BPFTOOL " $@
	$(Q)$(BPFTOOL) gen skeleton $< > $@

$(OBJS): %.o:%.c %.skel.h
	@echo "  CC " $@
	$(Q)$(CC) $(CFLAGS) -c $< -o $@

$(PROG): $(OBJS) $(LIBBPF)
	@echo "  LINK " $@
	$(Q)$(CC) $(OBJS) -o $@ $(LDLIBS)


clean:
	@echo "  CLEAN "
	$(Q)rm -f $(PROG) $(OBJS) *.bpf.o *.skel.h
	$(Q)rm -rf

test:
	$(info $(LIBBPF))

