# kernel/Makefile
CLANG         ?= clang-15
LLC           ?= llc-15
BPFTOOL       ?= bpftool
KERNEL_SRCS   := src/radm_xdp.c src/radm_tc.c src/radm_tp.c
KERNEL_OBJS   := $(KERNEL_SRCS:.c=.o)
INCLUDES      := -I./include -I./src

CLANG_FLAGS   := -target bpf -O2 -g -Wall -Werror \
                 -D__TARGET_ARCH_x86 \
                 -mcpu=v3 \
                 $(INCLUDES)

.PHONY: all clean vmlinux

all: vmlinux $(KERNEL_OBJS)

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h

%.o: %.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o $@

clean:
	rm -f $(KERNEL_OBJS) include/vmlinux.h
