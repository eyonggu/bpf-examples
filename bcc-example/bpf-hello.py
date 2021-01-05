#!/usr/bin/python3

from bcc import BPF

BPF_PROGRAM = r"""
int hello(void *ctx) {
  bpf_trace_printk("Hello world! File opened\n");
  return 0;
}
"""



bpf = BPF(text=BPF_PROGRAM)
bpf.attach_kprobe(event=bpf.get_syscall_fnname("clone"), fn_name="hello")

while True:
    try:
        (_, _, _, _, _, msg_b) = bpf.trace_fields()
        msg = msg_b.decode('utf8')
        if "Hello world" in msg:
            print(msg)
    except ValueError:
        continue
    except KeyboardInterrupt:
        break

