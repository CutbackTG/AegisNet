import os
import numpy as np
import pandas as pd

OUTPUT_PATH = os.path.join("data", "sample_flows.csv")
os.makedirs("data", exist_ok=True)

num_rows = 5000

rng = np.random.default_rng(42)

bytes_in = rng.integers(100, 50000, size=num_rows)
bytes_out = rng.integers(100, 50000, size=num_rows)
packets = rng.integers(1, 200, size=num_rows)
duration = rng.random(num_rows) * 5.0  # 0–5 seconds

# Common ports, weighted towards typical web/ssh/dns
src_ports = rng.choice(
    [22, 53, 80, 443, 8080, 3389],
    size=num_rows,
    p=[0.1, 0.1, 0.3, 0.3, 0.1, 0.1],
)
dst_ports = rng.integers(1024, 65535, size=num_rows)

# 6=TCP, 17=UDP mostly TCP
protocols = rng.choice([6, 17], size=num_rows, p=[0.8, 0.2])

df = pd.DataFrame({
    "bytes_in": bytes_in,
    "bytes_out": bytes_out,
    "packets": packets,
    "duration": duration,
    "src_port": src_ports,
    "dst_port": dst_ports,
    "protocol": protocols,
})

df.to_csv(OUTPUT_PATH, index=False)
print(f"Wrote {num_rows} rows to {OUTPUT_PATH}")
