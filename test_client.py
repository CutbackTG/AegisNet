import requests

url = "http://127.0.0.1:8000/score"

normal_flow = {
    "features": {
        "bytes_in": 1500,
        "bytes_out": 2000,
        "packets": 25,
        "duration": 0.52,
        "src_port": 443,
        "dst_port": 50321,
        "protocol": 6
    }
}

weird_flow = {
    "features": {
        "bytes_in": 10000000,
        "bytes_out": 5,
        "packets": 1,
        "duration": 0.01,
        "src_port": 44444,
        "dst_port": 1,
        "protocol": 17
    }
}

for label, flow in [("normal", normal_flow), ("weird", weird_flow)]:
    r = requests.post(url, json=flow, timeout=5)
    print(label, "→", r.json())

url_bulk = "http://127.0.0.1:8000/score_bulk"

batch = {
    "flows": [
        {
            "bytes_in": 1500,
            "bytes_out": 2000,
            "packets": 25,
            "duration": 0.52,
            "src_port": 443,
            "dst_port": 50321,
            "protocol": 6,
        },
        {
            "bytes_in": 10000000,
            "bytes_out": 5,
            "packets": 1,
            "duration": 0.01,
            "src_port": 44444,
            "dst_port": 1,
            "protocol": 17,
        },
    ]
}

resp = requests.post(url_bulk, json=batch, timeout=5)
print(resp.json())
