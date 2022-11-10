# kp_tcp

A eBPF example of type kprobe! It measures tcp connection time.


It was originally based on blog: https://medium.com/@phylake/bottom-up-ebpf-d7ca9cbe8321,
but I modified to use bpftool to generate skeleton.

To see the kprobes after the user space program runs:
```sh
cat /sys/kernel/debug/kprobes/list
```

