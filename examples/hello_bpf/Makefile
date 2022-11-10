TOPDIR := $(abspath ../../)
PROG=hello_bpf
OBJS=$(patsubst %.c,%.o,$(filter-out %.bpf.c,$(wildcard *.c)))

include $(TOPDIR)/Makefile

