import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Tuple


FlowEntry = Tuple[float, str, int, float, float]
FlowQueue = Deque[FlowEntry]


@dataclass
class ThreatVerdict:
    label: str
    confidence: float
    reason: str


class ThreatClassifier:
    """
    Lightweight, explainable threat labeling based on rolling flow patterns.
    Keeps in-memory state; good for prototype and demos.
    """

    def __init__(self, window_s: int = 30) -> None:
        self.window_s = window_s
        self.by_src: Dict[str, FlowQueue] = defaultdict(lambda: deque())

    def _prune(self, q: FlowQueue, now: float) -> None:
        cutoff = now - self.window_s
        while q and q[0][0] < cutoff:
            q.popleft()

    def update(
        self,
        meta: Dict,
        features: Dict[str, float],
        anomaly_score: float,
    ) -> Optional[ThreatVerdict]:
        now = float(meta.get("timestamp") or time.time())
        src_ip = meta.get("src_ip")
        dst_ip = meta.get("dst_ip")

        dst_port = int(features.get("dst_port", 0))
        bytes_out = float(features.get("bytes_out", 0.0))
        packets = float(features.get("packets", 0.0))

        # If we don't have IP metadata, we can only give weak labels.
        if not src_ip or not dst_ip:
            if anomaly_score > 0.08:
                return ThreatVerdict(
                    label="Anomalous Activity",
                    confidence=0.35,
                    reason="High anomaly score without IP context",
                )
            return None

        q = self.by_src[str(src_ip)]
        q.append((now, str(dst_ip), dst_port, bytes_out, packets))
        self._prune(q, now)

        dst_ports = {p for _, _, p, _, _ in q if p > 0}
        dst_hosts = {h for _, h, _, _, _ in q if h}

        total_bytes_out = sum(b for _, _, _, b, _ in q)
        total_packets = sum(pk for _, _, _, _, pk in q)

        # 1) Port scan
        if len(dst_ports) >= 30 and anomaly_score > 0.03:
            reason = (
                f"{len(dst_ports)} dst ports in "
                f"{self.window_s}s from {src_ip}"
            )
            return ThreatVerdict(
                label="Port Scan Suspected",
                confidence=0.75,
                reason=reason,
            )

        # 2) Host sweep / lateral movement
        if len(dst_hosts) >= 20 and anomaly_score > 0.03:
            reason = (
                f"{len(dst_hosts)} dst hosts in "
                f"{self.window_s}s from {src_ip}"
            )
            return ThreatVerdict(
                label="Host Sweep / Lateral Movement",
                confidence=0.70,
                reason=reason,
            )

        # 3) Data exfiltration
        if total_bytes_out >= 50_000_000 and anomaly_score > 0.02:
            reason = (
                f"{int(total_bytes_out)} bytes_out in "
                f"{self.window_s}s from {src_ip}"
            )
            return ThreatVerdict(
                label="Data Exfiltration Suspected",
                confidence=0.70,
                reason=reason,
            )

        # 4) Traffic spike / flood
        if total_packets >= 50_000 and anomaly_score > 0.02:
            reason = (
                f"{int(total_packets)} packets in "
                f"{self.window_s}s from {src_ip}"
            )
            return ThreatVerdict(
                label="Traffic Spike / Flood Suspected",
                confidence=0.65,
                reason=reason,
            )

        # 5) Generic anomaly fallback
        if anomaly_score > 0.08:
            return ThreatVerdict(
                label="Anomalous Activity",
                confidence=0.50,
                reason="High reconstruction error",
            )

        return None
