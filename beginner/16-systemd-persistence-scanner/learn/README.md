# Learn — systemd persistence

## Units as persistence

systemd units can start programs at boot or on a timer. Attackers who gain root may add a unit so their code survives reboot. Defenders look for unusual unit names, writable executable paths, and download-and-execute commands.

## High-signal paths

A legitimate service usually runs from `/usr`, `/opt`, or `/etc`. An executable under `/tmp` or `/dev/shm` is suspicious because those locations are writable and often noexec, though attackers still try them.

## Why snapshot input

Reading real unit files requires root and varies by distribution. Snapshot input keeps tests deterministic and lets the scanner be used on collected evidence offline.
