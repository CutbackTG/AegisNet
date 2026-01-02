import socket
import time
from typing import Dict, Optional

import psutil
import requests


API_URL = "http://127.0.0.1:8000/ingest"
INTERVAL = 0.2  # seconds


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


def _safe_process_name(pid: Optional[int]) -> Optional[str]:
    if pid is None:
        return None
    try:
        return psutil.Process(pid).name()
    except Exception:
        return None


def collect_and_send() -> None:
    agent_id = _hostname()
    prev_net = psutil.net_io_counters()
    prev_time = time.time()

    print(f"[Agent] Started. Interval={INTERVAL}s -> {API_URL}")
    print(f"[Agent] agent_id={agent_id}")

    while True:
        time.sleep(INTERVAL)

        now = time.time()
        elapsed = now - prev_time
        prev_time = now

        net = psutil.net_io_counters()

        delta_in = net.bytes_recv - prev_net.bytes_recv
        delta_out = net.bytes_sent - prev_net.bytes_sent

        delta_pk_in = net.packets_recv - prev_net.packets_recv
        delta_pk_out = net.packets_sent - prev_net.packets_sent
        delta_packets = delta_pk_in + delta_pk_out

        prev_net = net

        conns = psutil.net_connections(kind="tcp")
        active = [
            c for c in conns
            if c.raddr and c.status == psutil.CONN_ESTABLISHED
        ]

        if not active:
            continue

        per_in = float(delta_in) / len(active) if delta_in > 0 else 0.0
        per_out = float(delta_out) / len(active) if delta_out > 0 else 0.0
        per_pk = (
            float(delta_packets) / len(active)
            if delta_packets > 0
            else 0.0
        )

        for c in active:
            src_ip = getattr(c.laddr, "ip", None)
            dst_ip = getattr(c.raddr, "ip", None)

            src_port = getattr(c.laddr, "port", None)
            dst_port = getattr(c.raddr, "port", None)

            if src_port is None or dst_port is None:
                continue

            process_name = _safe_process_name(getattr(c, "pid", None))

            payload: Dict[str, object] = {
                "meta": {
                    "agent_id": agent_id,
                    "src_ip": str(src_ip) if src_ip else None,
                    "dst_ip": str(dst_ip) if dst_ip else None,
                    "process": process_name,
                    "timestamp": now,
                },
                "features": {
                    "bytes_in": per_in,
                    "bytes_out": per_out,
                    "packets": per_pk,
                    "duration": float(elapsed),
                    "src_port": float(src_port),
                    "dst_port": float(dst_port),
                    "protocol": 6.0,
                },
            }

            try:
                resp = requests.post(API_URL, json=payload, timeout=0.5)
                if resp.status_code != 200:
                    print(
                        "[Agent] /ingest returned",
                        resp.status_code,
                    )
            except Exception:
                # Ignore failures (server might not be ready or restarting)
                pass


def main() -> None:
    try:
        collect_and_send()
    except KeyboardInterrupt:
        print("\n[Agent] Stopped.")


if __name__ == "__main__":
    main()
