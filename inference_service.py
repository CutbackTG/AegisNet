import asyncio
import json
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from anomaly_scorer import AnomalyScorer
from schemas import IngestEvent
from threat_classifier import ThreatClassifier


app = FastAPI(title="AegisNet Anomaly Scoring API")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

scorer: Optional[AnomalyScorer] = None

threats = ThreatClassifier(window_s=30)

MAX_RECENT = 64
recent_results: Deque[Dict[str, Any]] = deque(maxlen=MAX_RECENT)

subscribers: List[asyncio.Queue] = []


class FlowFeatures(BaseModel):
    features: Dict[str, float]


class FlowBatch(BaseModel):
    flows: List[Dict[str, float]]


@app.on_event("startup")
def load_model() -> None:
    global scorer
    scorer = AnomalyScorer("autoencoder.pt")
    print("[OK] Model loaded")


def _sse_payload(item: Dict[str, Any]) -> str:
    return f"data: {json.dumps(item)}\n\n"


async def _broadcast(item: Dict[str, Any]) -> None:
    dead: List[asyncio.Queue] = []
    for q in subscribers:
        try:
            q.put_nowait(item)
        except Exception:
            dead.append(q)

    for q in dead:
        if q in subscribers:
            subscribers.remove(q)


def _log_result(
    flow: Dict[str, Any],
    score: float,
    is_suspicious: bool,
) -> None:
    item = {
        "flow": flow,
        "score": float(score),
        "is_suspicious": bool(is_suspicious),
    }
    recent_results.appendleft(item)

    try:
        loop = asyncio.get_running_loop()
        loop.create_task(_broadcast({"type": "event", "data": item}))
    except RuntimeError:
        # No running loop (unlikely during normal request handling)
        pass


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    device = "unknown"
    if scorer is not None:
        device = scorer.device

    last = recent_results[0] if recent_results else None
    last_flow = last.get("flow") if last else None

    context = {
        "request": request,
        "model_device": device,
        "results": list(recent_results),
        "last_score": last.get("score") if last else None,
        "last_is_suspicious": last.get("is_suspicious") if last else None,
        "last_flow": last_flow,
    }
    return templates.TemplateResponse("dashboard.html", context)


@app.get("/api/recent")
def api_recent(limit: int = Query(default=64, ge=1, le=256)) -> Dict[str, Any]:
    items = list(recent_results)[:limit]
    return {"results": items}


@app.get("/events")
async def events() -> StreamingResponse:
    q: asyncio.Queue = asyncio.Queue(maxsize=256)
    subscribers.append(q)

    async def gen():
        try:
            yield _sse_payload({"type": "connected"})
            while True:
                msg = await q.get()
                yield _sse_payload(msg)
        except asyncio.CancelledError:
            raise
        finally:
            if q in subscribers:
                subscribers.remove(q)

    return StreamingResponse(gen(), media_type="text/event-stream")


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
def score_flow(flow: FlowFeatures) -> Dict[str, Any]:
    assert scorer is not None

    score = scorer.score(flow.features)
    is_suspicious = score > 0.05
    _log_result(flow.features, score, is_suspicious)

    return {
        "anomaly_score": score,
        "is_suspicious": is_suspicious,
    }


@app.post("/score_bulk")
def score_flows(batch: FlowBatch) -> Dict[str, Any]:
    assert scorer is not None

    scores = scorer.score_batch(batch.flows)

    results: List[Dict[str, Any]] = []
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


@app.post("/ingest")
def ingest(event: IngestEvent) -> Dict[str, Any]:
    assert scorer is not None

    score = scorer.score(event.features)
    is_suspicious = score > 0.05

    verdict = threats.update(
        meta=event.meta.model_dump(),
        features=event.features,
        anomaly_score=score,
    )

    payload: Dict[str, Any] = {
        "anomaly_score": score,
        "is_suspicious": is_suspicious,
        "threat": None,
    }

    if verdict:
        payload["threat"] = {
            "label": verdict.label,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
        }

    # Log to dashboard ring buffer with enrichment for display
    log_item: Dict[str, Any] = dict(event.features)

    if event.meta.src_ip:
        log_item["src_ip"] = event.meta.src_ip
    if event.meta.dst_ip:
        log_item["dst_ip"] = event.meta.dst_ip

    if verdict:
        log_item["threat_label"] = verdict.label
        log_item["threat_confidence"] = verdict.confidence
        log_item["threat_reason"] = verdict.reason

    _log_result(log_item, score, is_suspicious)
    return payload
