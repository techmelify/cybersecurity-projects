#!/usr/bin/env python3
"""Detect deauthentication floods in a synthetic 802.11 event log.

The detector reads text lines supplied by the caller (a file via the CLI).
There is no radio access, no live capture, and no injection capability.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from typing import Iterable, Mapping, Sequence

__all__ = [
    "DetectionConfig",
    "FrameEvent",
    "ReceiverAlert",
    "ApAlert",
    "DetectionReport",
    "reason_description",
    "parse_event",
    "parse_events",
    "detect_floods",
    "main",
]

_FRAME_LINE = re.compile(r"^(?P<time>\S+)\s+(?P<kind>deauth|disassoc)\b(?P<rest>.*)$", re.IGNORECASE)
_FIELD = re.compile(r"(?P<key>[A-Za-z_][A-Za-z0-9_-]*)=(?P<value>\S+)")
_MAC = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$", re.IGNORECASE)

_REASON_DESCRIPTIONS: Mapping[int, str] = {
    1: "unspecified reason",
    2: "previous authentication no longer valid",
    3: "leaving network or ESS",
    4: "disassociated due to inactivity",
    5: "disassociated because AP cannot handle all associated stations",
    6: "class 2 frame received from non-authenticated station",
    7: "class 3 frame received from non-associated station",
    8: "disassociated because sending station is leaving",
    9: "deauthenticated because station is not authenticated",
    10: "deauthenticated because previous authentication expired",
}


@dataclass(frozen=True)
class DetectionConfig:
    """Thresholds for receiver-level and AP-level floods."""

    receiver_threshold: int = 8
    receiver_window: timedelta = timedelta(seconds=10)
    ap_threshold: int = 20
    ap_window: timedelta = timedelta(seconds=10)
    min_unique_receivers: int = 3


@dataclass(frozen=True)
class FrameEvent:
    """One parsed deauth/disassoc frame from the log."""

    time: datetime
    kind: str
    receiver: str
    bssid: str
    reason: int
    rssi: int | None


@dataclass(frozen=True)
class ReceiverAlert:
    """A flood against one receiver on one access point."""

    receiver: str
    bssid: str
    count: int
    window_seconds: int
    first_seen: datetime
    last_seen: datetime
    kinds: tuple[str, ...]
    reasons: tuple[int, ...]
    severity: str

    @property
    def message(self) -> str:
        return (
            f"{self.severity.upper()} receiver flood {self.receiver} @ {self.bssid}: "
            f"{self.count} frames / {self.window_seconds}s, reasons={list(self.reasons)}"
        )


@dataclass(frozen=True)
class ApAlert:
    """A broad flood spanning several receivers on one access point."""

    bssid: str
    count: int
    unique_receivers: int
    window_seconds: int
    first_seen: datetime
    last_seen: datetime
    severity: str

    @property
    def message(self) -> str:
        return (
            f"{self.severity.upper()} AP flood {self.bssid}: {self.count} frames, "
            f"{self.unique_receivers} receivers / {self.window_seconds}s"
        )


@dataclass(frozen=True)
class DetectionReport:
    """Aggregate alerts for one event log."""

    receiver_alerts: tuple[ReceiverAlert, ...]
    ap_alerts: tuple[ApAlert, ...]
    total_events: int

    @property
    def alert_count(self) -> int:
        return len(self.receiver_alerts) + len(self.ap_alerts)

    @property
    def ok(self) -> bool:
        return self.alert_count == 0


def reason_description(code: int) -> str:
    """Return the human-readable 802.11 reason code, if known."""

    return _REASON_DESCRIPTIONS.get(code, f"unknown reason {code}")


def parse_event(line: str) -> FrameEvent | None:
    """Parse one log line; return ``None`` for unrelated lines.

    A line that looks like a frame but has invalid fields raises ``ValueError``.
    """

    match = _FRAME_LINE.match(line.strip())
    if not match:
        return None

    fields = {key: value for key, value in _FIELD.findall(match.group("rest"))}
    receiver = fields.get("receiver", "")
    bssid = fields.get("ap", fields.get("bssid", ""))
    if not _MAC.fullmatch(receiver) or not _MAC.fullmatch(bssid):
        raise ValueError(f"invalid MAC address in line: {line.strip()}")

    try:
        reason = int(fields.get("reason", "1"))
        rssi = int(fields["rssi"]) if "rssi" in fields else None
        stamp = datetime.fromisoformat(match.group("time").removesuffix("Z"))
    except (ValueError, KeyError) as exc:
        raise ValueError(f"invalid frame fields in line: {line.strip()}") from exc

    return FrameEvent(stamp, match.group("kind").lower(), receiver.lower(), bssid.lower(), reason, rssi)


def parse_events(lines: Iterable[str]) -> tuple[FrameEvent, ...]:
    """Parse an iterable of log lines, ignoring unrelated ones."""

    events: list[FrameEvent] = []
    for line in lines:
        event = parse_event(line)
        if event is not None:
            events.append(event)
    return tuple(sorted(events, key=lambda e: (e.time, e.receiver, e.bssid)))


def _largest_cluster(events: Sequence[FrameEvent], window: timedelta) -> list[FrameEvent]:
    ordered = sorted(events, key=lambda e: e.time)
    best: list[FrameEvent] = []
    for start in ordered:
        cluster = [event for event in ordered if start.time <= event.time <= start.time + window]
        if len(cluster) > len(best):
            best = cluster
    return best


def detect_floods(events: Sequence[FrameEvent], config: DetectionConfig | None = None) -> DetectionReport:
    """Group frames by receiver/AP and access point, then flag floods."""

    settings = config or DetectionConfig()
    by_pair: dict[tuple[str, str], list[FrameEvent]] = {}
    by_ap: dict[str, list[FrameEvent]] = {}
    for event in events:
        by_pair.setdefault((event.receiver, event.bssid), []).append(event)
        by_ap.setdefault(event.bssid, []).append(event)

    receiver_alerts: list[ReceiverAlert] = []
    for (receiver, bssid), frames in sorted(by_pair.items()):
        cluster = _largest_cluster(frames, settings.receiver_window)
        if len(cluster) < settings.receiver_threshold:
            continue
        severity = "critical" if len(cluster) >= 2 * settings.receiver_threshold else "high"
        receiver_alerts.append(
            ReceiverAlert(
                receiver,
                bssid,
                len(cluster),
                int(settings.receiver_window.total_seconds()),
                cluster[0].time,
                cluster[-1].time,
                tuple(sorted({frame.kind for frame in cluster})),
                tuple(sorted({frame.reason for frame in cluster})),
                severity,
            )
        )

    ap_alerts: list[ApAlert] = []
    for bssid, frames in sorted(by_ap.items()):
        cluster = _largest_cluster(frames, settings.ap_window)
        receivers = {frame.receiver for frame in cluster}
        if len(cluster) < settings.ap_threshold or len(receivers) < settings.min_unique_receivers:
            continue
        severity = "critical" if len(cluster) >= 2 * settings.ap_threshold else "high"
        ap_alerts.append(
            ApAlert(
                bssid,
                len(cluster),
                len(receivers),
                int(settings.ap_window.total_seconds()),
                cluster[0].time,
                cluster[-1].time,
                severity,
            )
        )

    return DetectionReport(tuple(receiver_alerts), tuple(ap_alerts), len(events))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Detect deauth floods in a synthetic event log.")
    parser.add_argument("log", help="local text log of 802.11 deauth/disassoc events")
    parser.add_argument("--receiver-threshold", type=int, default=DetectionConfig.receiver_threshold)
    parser.add_argument("--ap-threshold", type=int, default=DetectionConfig.ap_threshold)
    parser.add_argument("--json", action="store_true", help="emit JSON alerts")
    args = parser.parse_args(argv)

    from pathlib import Path

    try:
        events = parse_events(Path(args.log).read_text(encoding="utf-8").splitlines())
    except ValueError as exc:
        parser.error(str(exc))
        return 2

    config = DetectionConfig(
        receiver_threshold=args.receiver_threshold,
        ap_threshold=args.ap_threshold,
    )
    report = detect_floods(events, config)

    if args.json:
        print(
            json.dumps(
                {
                    "receiver_alerts": [asdict(a) for a in report.receiver_alerts],
                    "ap_alerts": [asdict(a) for a in report.ap_alerts],
                    "total_events": report.total_events,
                },
                indent=2,
                default=str,
            )
        )
    else:
        for alert in report.receiver_alerts:
            print(alert.message)
        for alert in report.ap_alerts:
            print(alert.message)
        print(f"{report.alert_count} alert(s) from {report.total_events} frame(s)")
    return 1 if report.alert_count else 0


if __name__ == "__main__":
    sys.exit(main())
