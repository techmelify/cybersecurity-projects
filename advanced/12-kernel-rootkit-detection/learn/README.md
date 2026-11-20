# Learn — syscall snapshot indicators

## Syscall metadata

A syscall table maps numbers to handler functions. A snapshot can also record the module that owns each handler and an expected handler for comparison. Rootkits are associated with changing those mappings or hiding evidence of processes.

## Three comparisons

- **Hook indicator:** observed handler differs from the expected handler recorded in the snapshot.
- **Owner indicator:** owning module is not in the allowed-module set.
- **Visibility indicator:** a process is explicitly hidden or missing from the proc/ps views recorded in the snapshot.

Each is a comparison between supplied fields. The tool never derives ground truth from a live machine.

## Why a baseline matters

Without an expected handler, a symbolic name cannot be judged safe or unsafe. The synthetic snapshot supplies that baseline explicitly so the exercise remains deterministic and honest about its assumptions.

## Limitations in real systems

Real kernels use indirect calls, trampolines, signed modules, and legitimate third-party drivers. A mismatch can be benign, and a sophisticated rootkit can leave the snapshot looking clean. This project teaches metadata comparison only.

## Exercises

- Add a rule for two syscalls sharing the same handler address.
- Add a rule for missing entries in an expected syscall number range.
- Add a pure function that summarizes detections per module.
