from __future__ import annotations

from collections import deque
from typing import Any, Deque, Dict, List

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from anomaly_scorer import AnomalyScorer
from schemas import IngestEvent
from threat_classifier import ThreatClassifier

app = FastAPI(title="AegisNet Anomaly Scoring API")

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

scorer: AnomalyScorer | None = None

MAX_RECENT = 64
recent_results: Deque[Dict[str, Any]] = deque(maxlen=MAX_RECENT)

threats = ThreatClassifier(window_s=30)


class FlowFeatures(BaseModel):
    features: Dict[str, float]


class FlowBatch(BaseModel):
    flows: List[Dict[str, float]]


@app.on_event("startup")
def load_model() -> None:
    global scorer
    scorer = AnomalyScorer("autoencoder.pt")
    print("[OK] Model loaded")


def _log_result(flow: Dict[str, Any], score: float, is_suspicious: bool) -> None:
    recent_results.appendleft(
        {
            "flow": flow,
            "score": score,
            "is_suspicious": is_suspicious,
        }
    )


def _meta_to_dict(meta_obj: Any) -> Dict[str, Any]:
    """
    Support both Pydantic v2 (model_dump) and v1 (dict).
    """
    if hasattr(meta_obj, "model_dump"):
        return meta_obj.model_dump()
    return meta_obj.dict()  # type: ignore[no-any-return]


@app.get("/", response_class=HTMLResponse)
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request) -> HTMLResponse:
    device = scorer.device if scorer is not None else "unknown"
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

    context = {
        "request": request,
        "model_device": scorer.device,
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

    meta = _meta_to_dict(event.meta)

    verdict = threats.update(
        meta=meta,
        features=event.features,
        anomaly_score=score,
    )

    payload: Dict[str, Any] = {
        "anomaly_score": score,
        "is_suspicious": is_suspicious,
        "threat": None,
    }

    if verdict is not None:
        payload["threat"] = {
            "label": verdict.label,
            "confidence": verdict.confidence,
            "reason": verdict.reason,
        }

    log_item: Dict[str, Any] = dict(event.features)

    src_ip = getattr(event.meta, "src_ip", None)
    dst_ip = getattr(event.meta, "dst_ip", None)

    if src_ip:
        log_item["src_ip"] = src_ip
    if dst_ip:
        log_item["dst_ip"] = dst_ip

    if verdict is not None:
        log_item["threat_label"] = verdict.label
        log_item["threat_confidence"] = verdict.confidence

    _log_result(log_item, score, is_suspicious)
    return payload
