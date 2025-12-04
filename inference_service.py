from collections import deque
from typing import Deque, Dict, List

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from anomaly_scorer import AnomalyScorer


app = FastAPI(title="AegisNet Anomaly Scoring API")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

scorer: AnomalyScorer | None = None

MAX_RECENT = 64
recent_results: Deque[Dict] = deque(maxlen=MAX_RECENT)


class FlowFeatures(BaseModel):
    features: Dict[str, float]


class FlowBatch(BaseModel):
    flows: List[Dict[str, float]]


@app.on_event("startup")
def load_model() -> None:
    global scorer
    scorer = AnomalyScorer("autoencoder.pt")
    print("[OK] Model loaded")


def _log_result(flow: Dict[str, float], score: float,
                is_suspicious: bool) -> None:
    recent_results.appendleft(
        {
            "flow": flow,
            "score": score,
            "is_suspicious": is_suspicious,
        }
    )


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    device = "unknown"
    if scorer is not None:
        device = scorer.device

    last = recent_results[0] if recent_results else None

    context = {
        "request": request,
        "model_device": device,
        "results": list(recent_results),
        "last_score": last["score"] if last else None,
        "last_is_suspicious": last["is_suspicious"] if last else None,
        "last_flow": last["flow"] if last else None,
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.post("/ui/score", response_class=HTMLResponse)
async def ui_score(
    request: Request,
    bytes_in: float = Form(...),
    bytes_out: float = Form(...),
    packets: float = Form(...),
    duration: float = Form(...),
    src_port: float = Form(...),
    dst_port: float = Form(...),
    protocol: float = Form(...),
) -> HTMLResponse:
    assert scorer is not None

    flow = {
        "bytes_in": float(bytes_in),
        "bytes_out": float(bytes_out),
        "packets": float(packets),
        "duration": float(duration),
        "src_port": float(src_port),
        "dst_port": float(dst_port),
        "protocol": float(protocol),
    }

    score = scorer.score(flow)
    is_suspicious = score > 0.05
    _log_result(flow, score, is_suspicious)

    device = scorer.device
    context = {
        "request": request,
        "model_device": device,
        "results": list(recent_results),
        "last_score": score,
        "last_is_suspicious": is_suspicious,
        "last_flow": flow,
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.post("/score")
def score_flow(flow: FlowFeatures):
    assert scorer is not None
    score = scorer.score(flow.features)
    is_suspicious = score > 0.05

    _log_result(flow.features, score, is_suspicious)

    return {
        "anomaly_score": score,
        "is_suspicious": is_suspicious,
    }


@app.post("/score_bulk")
def score_flows(batch: FlowBatch):
    assert scorer is not None

    scores = scorer.score_batch(batch.flows)
    results = []
    for idx, (flow, score) in enumerate(zip(batch.flows, scores)):
        is_suspicious = score > 0.05
        _log_result(flow, score, is_suspicious)
        results.append(
            {
                "index": idx,
                "anomaly_score": score,
                "is_suspicious": is_suspicious,
            }
        )

    return {"results": results}
