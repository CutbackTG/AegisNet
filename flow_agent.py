import random
import socket
import time
from typing import Dict, Optional

import psutil
import requests


API_URL = "http://127.0.0.1:8000/ingest"
INTERVAL = 0.2  # seconds

MAX_CONNECTIONS_PER_TICK = 25  # prevents spamming the API
TIMEOUT_S = 0.5


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


def _get_active_tcp_connections():
    # net_connections can be costly; keep it isolated for easy tuning later.
    conns = psutil.net_connections(kind="tcp")
    active = [
        c for c in conns
        if c.raddr and c.status == psutil.CONN_ESTABLISHED
    ]
    return active


def collect_and_send() -> None:
    agent_id = _hostname()
    prev_net = psutil.net_io_counters()
    prev_time = time.time()

    session = requests.Session()

    sent_total = 0
    dropped_total = 0
    bad_status_total = 0

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

        try:
            active = _get_active_tcp_connections()
        except Exception:
            dropped_total += 1
            continue

        if not active:
            continue

        # Cap connections per tick to avoid overwhelming the API
        if len(active) > MAX_CONNECTIONS_PER_TICK:
            active = random.sample(active, MAX_CONNECTIONS_PER_TICK)

        n = len(active)
        per_in = float(delta_in) / n if delta_in > 0 else 0.0
        per_out = float(delta_out) / n if delta_out > 0 else 0.0
        per_pk = float(delta_packets) / n if delta_packets > 0 else 0.0

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
                    "bytes_in": float(per_in),
                    "bytes_out": float(per_out),
                    "packets": float(per_pk),
                    "duration": float(elapsed),
                    "src_port": float(src_port),
                    "dst_port": float(dst_port),
                    "protocol": 6.0,
                },
            }

            try:
                resp = session.post(API_URL, json=payload, timeout=TIMEOUT_S)
                sent_total += 1

                if resp.status_code != 200:
                    bad_status_total += 1
            except Exception:
                dropped_total += 1

        # Lightweight heartbeat every ~5s so you know it's alive
        if sent_total and (sent_total % 250 == 0):
            print(
                f"[Agent] sent={sent_total} "
                f"bad_status={bad_status_total} "
                f"dropped={dropped_total} "
                f"active_sampled={n}"
            )


def main() -> None:
    try:
        collect_and_send()
    except KeyboardInterrupt:
        print("\n[Agent] Stopped.")


if __name__ == "__main__":
    main()
