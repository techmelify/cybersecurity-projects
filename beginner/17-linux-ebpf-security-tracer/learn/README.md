# Learn — security tracing

## eBPF in one paragraph

eBPF lets a program run sandboxed code in the kernel in response to events such as `execve` or `connect`. Security tools use it to observe process behaviour with low overhead. A tracer emits events; a separate analyzer decides which ones matter.

## Why split the analyzer out

Live tracing needs privileges and produces different results on every host. Feeding the analyzer recorded events makes detection rules testable and reusable. The same rules can later consume events from eBPF, auditd, or an EDR agent.

## Detection thinking

No single event proves compromise. Rules look for context: a web server spawning a shell, or execution from a writable directory. Combining signals reduces false positives.
