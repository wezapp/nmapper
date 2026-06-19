from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


class AuthRequest(BaseModel):
    api_key: str = Field(..., min_length=1, max_length=200)


class ScanProfile(str, Enum):
    discovery = "discovery"
    quick = "quick"
    standard = "standard"
    full = "full"
    stealth = "stealth"


class ScanStatus(str, Enum):
    queued = "queued"
    running = "running"
    done = "done"
    error = "error"
    cancelled = "cancelled"


class ScanRequest(BaseModel):
    # Accepte une ou plusieurs cibles space/comma/newline-séparées (validées dans validator.py)
    target: str = Field(..., min_length=7, max_length=2000)
    profile: ScanProfile = ScanProfile.quick
    ports: Optional[str] = Field(None, max_length=500)
    vlan_name: Optional[str] = Field(None, max_length=64)


class ScanResponse(BaseModel):
    id: str
    status: ScanStatus
    target: str
    profile: str
    vlan_name: Optional[str]
    created_at: str
    started_at: Optional[str]
    finished_at: Optional[str]
    error: Optional[str] = Field(None, max_length=500)
    result_available: bool


class ScanListResponse(BaseModel):
    scans: list[ScanResponse]
    total: int
