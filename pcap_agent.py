import socket
import time
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

import pyshark
import requests


API_URL = "http://127.0.0.1:8000/ingest"

FLUSH_INTERVAL = 1.0
FLOW_TTL = 30.0
MAX_FLUSH = 200


def _hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "unknown-host"


@dataclass
class FlowAgg:
    first_ts: float
    last_ts: float
    bytes_in: float = 0.0
    bytes_out: float = 0.0
    packets: float = 0.0
    proto: float = 0.0
    src_port: float = 0.0
    dst_port: float = 0.0
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    process: Optional[str] = None


FlowKey = Tuple[str, str, int, int, int]


def _packet_len(pkt) -> int:
    try:
        return int(pkt.length)
    except Exception:
        try:
            return int(pkt.frame_info.len)
        except Exception:
            return 0


def _extract_5tuple(pkt) -> Optional[FlowKey]:
    try:
        if hasattr(pkt, "ip"):
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
        elif hasattr(pkt, "ipv6"):
            src_ip = pkt.ipv6.src
            dst_ip = pkt.ipv6.dst
        else:
            return None

        if hasattr(pkt, "tcp"):
            proto = 6
            src_port = int(pkt.tcp.srcport)
            dst_port = int(pkt.tcp.dstport)
        elif hasattr(pkt, "udp"):
            proto = 17
            src_port = int(pkt.udp.srcport)
            dst_port = int(pkt.udp.dstport)
        else:
            return None

        return (src_ip, dst_ip, src_port, dst_port, proto)

    except Exception:
        return None


def _flush(
    flows: Dict[FlowKey, FlowAgg],
    session: requests.Session,
    agent_id: str,
    now: float,
) -> None:
    cutoff = now - FLOW_TTL
    stale_keys = [
        key for key, agg in flows.items()
        if agg.last_ts < cutoff
    ]

    for key in stale_keys:
        flows.pop(key, None)

    if not flows:
        return

    items = sorted(
        flows.items(),
        key=lambda kv: kv[1].last_ts,
        reverse=True,
    )[:MAX_FLUSH]

    sent = 0
    for _, agg in items:
        duration = max(0.001, agg.last_ts - agg.first_ts)

        payload = {
            "meta": {
                "agent_id": agent_id,
                "src_ip": agg.src_ip,
                "dst_ip": agg.dst_ip,
                "process": agg.process,
                "timestamp": now,
            },
            "features": {
                "bytes_in": agg.bytes_in,
                "bytes_out": agg.bytes_out,
                "packets": agg.packets,
                "duration": duration,
                "src_port": agg.src_port,
                "dst_port": agg.dst_port,
                "protocol": agg.proto,
            },
        }

        try:
            resp = session.post(
                API_URL,
                json=payload,
                timeout=0.75,
            )
            if resp.status_code == 200:
                sent += 1
        except Exception:
            continue

    print(
        f"[PCAP Agent] flushed={sent} "
        f"active_flows={len(flows)}"
    )


def run_capture(interface: str, bpf: str = "tcp or udp") -> None:
    agent_id = _hostname()
    session = requests.Session()

    flows: Dict[FlowKey, FlowAgg] = {}
    last_flush = time.time()

    print(f"[PCAP Agent] agent_id={agent_id}")
    print(f"[PCAP Agent] interface={interface}")
    print(f"[PCAP Agent] filter={bpf}")
    print(f"[PCAP Agent] sending to {API_URL}")
    print("[PCAP Agent] starting capture (Ctrl+C to stop)")

    capture = pyshark.LiveCapture(
        interface=interface,
        bpf_filter=bpf,
    )

    try:
        for pkt in capture.sniff_continuously():
            now = time.time()
            key = _extract_5tuple(pkt)

            if key is None:
                continue

            plen = _packet_len(pkt)
            src_ip, dst_ip, src_port, dst_port, proto = key

            agg = flows.get(key)
            if agg is None:
                agg = FlowAgg(
                    first_ts=now,
                    last_ts=now,
                    proto=float(proto),
                    src_port=float(src_port),
                    dst_port=float(dst_port),
                    src_ip=str(src_ip),
                    dst_ip=str(dst_ip),
                )
                flows[key] = agg
            else:
                agg.last_ts = now

            agg.packets += 1.0
            agg.bytes_out += float(plen)

            if now - last_flush >= FLUSH_INTERVAL:
                _flush(
                    flows=flows,
                    session=session,
                    agent_id=agent_id,
                    now=now,
                )
                last_flush = now

    except KeyboardInterrupt:
        print("\n[PCAP Agent] stopping")

    finally:
        try:
            capture.close()
        except Exception:
            pass


def main() -> None:
    print("[PCAP Agent] available interfaces:")
    for iface in pyshark.tshark.tshark.get_tshark_interfaces():
        print(" -", iface)

    interface = input(
        "\nPaste interface name from list above:\n> "
    ).strip()

    if not interface:
        print("No interface provided. Exiting.")
        return

    run_capture(interface=interface)


if __name__ == "__main__":
    main()
