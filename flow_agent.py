import time
import psutil
import requests
import threading

API_URL = "http://127.0.0.1:8000/score"
INTERVAL = 0.2  # seconds (fast monitoring)


def collect_and_send():
    prev_net = psutil.net_io_counters()

    while True:
        time.sleep(INTERVAL)

        # Gather new network counters
        net = psutil.net_io_counters()

        bytes_in = net.bytes_recv - prev_net.bytes_recv
        bytes_out = net.bytes_sent - prev_net.bytes_sent

        packets_in = net.packets_recv - prev_net.packets_recv
        packets_out = net.packets_sent - prev_net.packets_sent
        packets = packets_in + packets_out

        prev_net = net

        # Active TCP connections
        conns = psutil.net_connections(kind="tcp")

        for c in conns:
            if not c.raddr:
                continue

            flow = {
                "features": {
                    "bytes_in": float(bytes_in),
                    "bytes_out": float(bytes_out),
                    "packets": float(packets),
                    "duration": INTERVAL,
                    "src_port": c.laddr.port,
                    "dst_port": c.raddr.port,
                    "protocol": 6,
                }
            }

            try:
                requests.post(
                    API_URL,
                    json=flow,
                    timeout=0.5
                )
            except Exception:
                # Ignore failures (server might not be ready)
                pass


def start_agent():
    thread = threading.Thread(
        target=collect_and_send,
        daemon=True
    )
    thread.start()
    print("Real-time network agent started (0.2s interval).")
    print(f"Sending live flow data to: {API_URL}")


if __name__ == "__main__":
    start_agent()
    while True:
        time.sleep(1)
