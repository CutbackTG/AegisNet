from typing import Dict, Optional
from pydantic import BaseModel


class FlowMeta(BaseModel):
    agent_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    process: Optional[str] = None
    timestamp: Optional[float] = None  # epoch seconds


class IngestEvent(BaseModel):
    meta: FlowMeta
    features: Dict[str, float]
