from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class AssetCreate(BaseModel):
    name: str
    asset_type: str
    criticality: str
    asset_value: float
    data_sensitivity: str
    department: str
    internet_exposure: bool = True
    exposure_factor: float = 0.8

class Asset(AssetCreate):
    id: int

class VulnerabilityCreate(BaseModel):
    cve_id: str
    title: str
    cvss_score: float
    exploitability: float
    asset_id: int
    category: str
    patch_available: bool = True
    exposure_level: str = 'Public Internet'
    threat_likelihood: float = 0.5
    description: str = ''

class Vulnerability(VulnerabilityCreate):
    id: int
    asset_name: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    sle: Optional[float] = None
    aro: Optional[float] = None
    ale: Optional[float] = None
    potential_loss: Optional[float] = None

class SecurityControl(BaseModel):
    id: int
    name: str
    category: str
    cost: float
    risk_reduction_pct: float
    loss_reduction_pct: float
    affected_asset_types: List[str]
    description: str
    implementation_time_weeks: int
    roi: Optional[float] = None
    expected_loss_avoided: Optional[float] = None

class OptimizationRequest(BaseModel):
    budget: float
    selected_controls: Optional[List[int]] = None

class WhatIfRequest(BaseModel):
    budget: float = 500000.0
    threat_likelihood_multiplier: float = 1.0
    asset_value_multiplier: float = 1.0
    cvss_multiplier: float = 1.0
    enabled_control_ids: Optional[List[int]] = None

class LoginRequest(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    username: str
    role: str
    token: str
