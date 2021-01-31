# Examples about sock

## sockmap

Test
```console
#window #1
nc -l 1234

#window #2
nc -l 4321

#window #3
./sockmap 127.0.0.1 1234 127.0.0.1 4321

#window #4
sudo cat /sys/kernel/debug/tracing/trace_pipe

#input something in #1 or #2

```
