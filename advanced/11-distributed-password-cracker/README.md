# 11 — Distributed Password Cracker

**Simulation only.** The upstream offensive password-cracking synopsis is replaced by a defensive lab that partitions a synthetic candidate workload and estimates bounded digest work. It does **not** recover passwords, attack real hashes, use real word lists, use GPUs, or use the network.

## What it does

- Generates obviously synthetic candidates such as `lab-00000-k3f9x2qa` from a seed
- Splits them into fixed-size chunks with explicit index ranges
- Assigns chunks to workers in deterministic round-robin order
- Estimates digest operations and bytes hashed for a chosen hash algorithm
- Optionally computes digests of synthetic candidates for demonstration; it never compares them to a target hash

No `--hash`, `--target`, word-list path, or GPU option exists.

## Run

```powershell
python password_lab_simulator.py --size 100 --seed 7 --chunk-size 10 --workers 3
python password_lab_simulator.py --size 100 --seed 7 --json
python password_lab_simulator.py --size 50 --algorithm sha512 --checks-per-candidate 2
```

## Test

```powershell
python -m unittest discover -s tests
```

15 tests. Standard library only; results are reproducible from the seed.

## Limitations

This is capacity-planning arithmetic, not a password-recovery tool. Timings, hardware throughput, network overhead, and real password distributions are deliberately absent. Do not use it to plan an attack against any system you do not own.
