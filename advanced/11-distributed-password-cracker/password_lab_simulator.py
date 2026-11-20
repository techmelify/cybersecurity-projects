#!/usr/bin/env python3
"""Deterministic workload simulation for a defensive password-cracking lab.

This tool partitions synthetic candidate strings and estimates bounded digest
work. It never compares against a target hash, uses real word lists, GPUs, or
the network, and performs no password recovery.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import string
import sys
from dataclasses import dataclass
from typing import Any, Sequence

ALGORITHMS: frozenset[str] = frozenset({"sha256", "sha512", "blake2b", "blake2s"})

__all__ = [
    "WorkChunk",
    "Assignment",
    "WorkEstimate",
    "ChunkSimulation",
    "SimulationReport",
    "build_synthetic_dictionary",
    "partition_workload",
    "assign_chunks",
    "estimate_work",
    "simulate_chunk",
    "build_simulation_report",
    "main",
]


@dataclass(frozen=True)
class WorkChunk:
    index: int
    start: int
    end: int
    candidates: tuple[str, ...]

    @property
    def size(self) -> int:
        return len(self.candidates)

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "start": self.start,
            "end_exclusive": self.end,
            "size": self.size,
            "candidates": list(self.candidates),
        }


@dataclass(frozen=True)
class Assignment:
    worker_id: int
    chunk_indexes: tuple[int, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "chunk_indexes": list(self.chunk_indexes),
        }


@dataclass(frozen=True)
class WorkEstimate:
    algorithm: str
    digest_size_bytes: int
    candidate_count: int
    checks_per_candidate: int
    digest_operations: int
    bytes_hashed: int
    chunk_count: int
    worker_count: int

    def as_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "digest_size_bytes": self.digest_size_bytes,
            "candidate_count": self.candidate_count,
            "checks_per_candidate": self.checks_per_candidate,
            "digest_operations": self.digest_operations,
            "bytes_hashed": self.bytes_hashed,
            "chunk_count": self.chunk_count,
            "worker_count": self.worker_count,
        }


@dataclass(frozen=True)
class ChunkSimulation:
    chunk_index: int
    candidate_count: int
    digest_operations: int
    first_digest_preview: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "chunk_index": self.chunk_index,
            "candidate_count": self.candidate_count,
            "digest_operations": self.digest_operations,
            "first_digest_preview": self.first_digest_preview,
        }


@dataclass(frozen=True)
class SimulationReport:
    seed: int
    chunks: tuple[WorkChunk, ...]
    assignments: tuple[Assignment, ...]
    estimate: WorkEstimate
    simulations: tuple[ChunkSimulation, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "note": "Simulation only: no real hashes, targets, GPUs, or network.",
            "seed": self.seed,
            "chunks": [chunk.as_dict() for chunk in self.chunks],
            "assignments": [assignment.as_dict() for assignment in self.assignments],
            "estimate": self.estimate.as_dict(),
            "simulations": [simulation.as_dict() for simulation in self.simulations],
        }

    def format_text(self) -> str:
        estimate = self.estimate
        lines = [
            "Simulation only: partitioned password workload (no real hashes or target attacks).",
            f"seed: {self.seed}",
            f"algorithm: {estimate.algorithm}",
            f"candidates: {estimate.candidate_count}",
            f"chunks: {estimate.chunk_count}",
            f"workers: {estimate.worker_count}",
            f"digest operations: {estimate.digest_operations}",
            f"bytes hashed: {estimate.bytes_hashed}",
            "",
            "Chunks:",
        ]
        for chunk in self.chunks:
            lines.append(f"  #{chunk.index}: [{chunk.start}, {chunk.end}) size={chunk.size}")
        lines.append("Assignments:")
        for assignment in self.assignments:
            lines.append(
                f"  worker {assignment.worker_id}: "
                f"chunks {list(assignment.chunk_indexes)}"
            )
        return "\n".join(lines)


def build_synthetic_dictionary(
    size: int, seed: int, prefix: str = "lab-"
) -> tuple[str, ...]:
    """Generate deterministic, obviously synthetic candidate strings."""
    if size < 0:
        raise ValueError("size must be non-negative")
    rng = random.Random(seed)
    alphabet = string.ascii_lowercase + string.digits
    candidates: list[str] = []
    for index in range(size):
        suffix = "".join(rng.choice(alphabet) for _ in range(8))
        candidates.append(f"{prefix}{index:05d}-{suffix}")
    return tuple(candidates)


def partition_workload(
    items: Sequence[str], chunk_size: int
) -> tuple[WorkChunk, ...]:
    """Split items into fixed-size, non-overlapping chunks."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be at least 1")
    chunks: list[WorkChunk] = []
    for index, start in enumerate(range(0, len(items), chunk_size)):
        end = min(start + chunk_size, len(items))
        chunks.append(WorkChunk(index, start, end, tuple(items[start:end])))
    return tuple(chunks)


def assign_chunks(
    chunks: Sequence[WorkChunk], worker_count: int
) -> tuple[Assignment, ...]:
    """Assign chunk indexes to workers in deterministic round-robin order."""
    if worker_count < 1:
        raise ValueError("worker_count must be at least 1")
    buckets: list[list[int]] = [[] for _ in range(worker_count)]
    for index, _ in enumerate(chunks):
        buckets[index % worker_count].append(index)
    return tuple(
        Assignment(worker_id, tuple(indexes))
        for worker_id, indexes in enumerate(buckets, start=1)
    )


def _validate_algorithm(algorithm: str) -> int:
    if algorithm not in ALGORITHMS:
        raise ValueError(
            "unsupported algorithm; choose from " + ", ".join(sorted(ALGORITHMS))
        )
    return hashlib.new(algorithm).digest_size


def estimate_work(
    chunks: Sequence[WorkChunk],
    assignments: Sequence[Assignment],
    algorithm: str = "sha256",
    checks_per_candidate: int = 1,
) -> WorkEstimate:
    """Estimate bounded digest counts without performing any comparison."""
    digest_size = _validate_algorithm(algorithm)
    if checks_per_candidate < 1:
        raise ValueError("checks_per_candidate must be at least 1")
    candidates = [candidate for chunk in chunks for candidate in chunk.candidates]
    bytes_hashed = sum(len(candidate.encode("utf-8")) for candidate in candidates)
    return WorkEstimate(
        algorithm=algorithm,
        digest_size_bytes=digest_size,
        candidate_count=len(candidates),
        checks_per_candidate=checks_per_candidate,
        digest_operations=len(candidates) * checks_per_candidate,
        bytes_hashed=bytes_hashed * checks_per_candidate,
        chunk_count=len(chunks),
        worker_count=len(assignments),
    )


def simulate_chunk(chunk: WorkChunk, algorithm: str = "sha256") -> ChunkSimulation:
    """Compute synthetic digests only; never compare them to a target."""
    _validate_algorithm(algorithm)
    previews = [
        hashlib.new(algorithm, candidate.encode("utf-8")).hexdigest()
        for candidate in chunk.candidates
    ]
    return ChunkSimulation(
        chunk_index=chunk.index,
        candidate_count=chunk.size,
        digest_operations=len(previews),
        first_digest_preview=previews[0] if previews else "",
    )


def build_simulation_report(
    size: int,
    seed: int,
    chunk_size: int,
    worker_count: int,
    algorithm: str = "sha256",
    checks_per_candidate: int = 1,
) -> SimulationReport:
    """Build a complete deterministic simulation report."""
    candidates = build_synthetic_dictionary(size, seed)
    chunks = partition_workload(candidates, chunk_size)
    assignments = assign_chunks(chunks, worker_count)
    estimate = estimate_work(chunks, assignments, algorithm, checks_per_candidate)
    simulations = tuple(simulate_chunk(chunk, algorithm) for chunk in chunks)
    return SimulationReport(seed, chunks, assignments, estimate, simulations)


def _positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return number


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Simulate partitioned password-workload planning only."
    )
    parser.add_argument("--size", type=_positive_int, default=100)
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--chunk-size", type=_positive_int, default=10)
    parser.add_argument("--workers", type=_positive_int, default=3)
    parser.add_argument(
        "--algorithm", choices=sorted(ALGORITHMS), default="sha256"
    )
    parser.add_argument("--checks-per-candidate", type=_positive_int, default=1)
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = parser.parse_args(argv)

    try:
        report = build_simulation_report(
            size=args.size,
            seed=args.seed,
            chunk_size=args.chunk_size,
            worker_count=args.workers,
            algorithm=args.algorithm,
            checks_per_candidate=args.checks_per_candidate,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(report.format_text())
    return 0


if __name__ == "__main__":
    sys.exit(main())
