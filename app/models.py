"""
CyberQuant AI - Data Models & Validation Schemas
Defines Pydantic schemas for request validation and response serialization.
"""
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field

# ==============================================================================
# AUTHENTICATION & ACCESS CONTROL SCHEMAS
# ==============================================================================

class LoginRequest(BaseModel):
    username: str = Field(..., description="Administrator username or authorized email")
    password: str = Field(..., description="User password")

class LoginResponse(BaseModel):
    success: bool
    username: str
    role: str
    token: str

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., description="Designated administrative recovery email")

class VerifyOtpRequest(BaseModel):
    email: str
    otp: str

class VerifyOtpSkipRequest(BaseModel):
    email: str
    otp: str

class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str

# ==============================================================================
# ASSET MANAGEMENT SCHEMAS
# ==============================================================================

class AssetCreate(BaseModel):
    name: str = Field(..., example="Primary Transaction Database")
    asset_type: str = Field(..., example="Database")
    criticality: str = Field(..., example="Critical", description="Critical, High, Medium, or Low")
    asset_value: float = Field(..., gt=0, example=5000000.0, description="Replacement / business value in INR")
    data_sensitivity: str = Field(..., example="Confidential / PII")
    department: str = Field(..., example="Core Engineering and IT")
    internet_exposure: int = Field(1, ge=0, le=1, description="1 for internet-exposed, 0 for internal")
    exposure_factor: float = Field(0.75, ge=0.01, le=1.0, description="FAIR Exposure Factor percentage (0.01 - 1.0)")

class AssetUpdate(BaseModel):
    name: Optional[str] = None
    asset_type: Optional[str] = None
    criticality: Optional[str] = None
    asset_value: Optional[float] = Field(None, gt=0)
    data_sensitivity: Optional[str] = None
    department: Optional[str] = None
    internet_exposure: Optional[int] = Field(None, ge=0, le=1)
    exposure_factor: Optional[float] = Field(None, ge=0.01, le=1.0)

class AssetResponse(AssetCreate):
    id: int

# ==============================================================================
# VULNERABILITY MANAGEMENT SCHEMAS
# ==============================================================================

class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(..., example="CVE-2024-3400")
    title: str = Field(..., example="Critical SQL Injection and Remote Code Execution in API")
    cvss_score: float = Field(..., ge=0.0, le=10.0, example=9.8)
    exploitability: float = Field(..., ge=0.0, le=1.0, example=0.90)
    asset_id: int = Field(..., gt=0)
    category: str = Field(..., example="Remote Code Execution")
    patch_available: int = Field(1, ge=0, le=1)
    exposure_level: str = Field("Public Internet", example="Public Internet")
    threat_likelihood: float = Field(0.50, ge=0.01, le=1.0, example=0.50)
    description: str = Field("", example="Flaw in public API endpoints allowing unauthenticated RCE.")

class VulnerabilityUpdate(BaseModel):
    cve_id: Optional[str] = None
    title: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    exploitability: Optional[float] = Field(None, ge=0.0, le=1.0)
    asset_id: Optional[int] = None
    category: Optional[str] = None
    patch_available: Optional[int] = Field(None, ge=0, le=1)
    exposure_level: Optional[str] = None
    threat_likelihood: Optional[float] = Field(None, ge=0.01, le=1.0)
    description: Optional[str] = None

class VulnerabilityResponse(VulnerabilityCreate):
    id: int

# ==============================================================================
# SECURITY CONTROLS & DEFENSIVE MITIGATION SCHEMAS
# ==============================================================================

class SecurityControlCreate(BaseModel):
    name: str = Field(..., example="Vulnerability Patching and Hotfix Automation")
    category: str = Field(..., example="Patch Management")
    cost: float = Field(..., ge=0, example=120000.0, description="Cost in INR")
    risk_reduction_pct: float = Field(..., ge=0, le=100.0, example=38.0)
    loss_reduction_pct: float = Field(..., ge=0, le=100.0, example=42.0)
    affected_asset_types: List[str] = Field(..., example=["Database", "Web Application"])
    description: str = Field(..., example="Automated zero-day patch pipeline for critical RCE.")
    implementation_time_weeks: int = Field(..., ge=1, example=2)

class SecurityControlUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    cost: Optional[float] = Field(None, ge=0)
    risk_reduction_pct: Optional[float] = Field(None, ge=0, le=100.0)
    loss_reduction_pct: Optional[float] = Field(None, ge=0, le=100.0)
    affected_asset_types: Optional[List[str]] = None
    description: Optional[str] = None
    implementation_time_weeks: Optional[int] = Field(None, ge=1)

class SecurityControlResponse(BaseModel):
    id: int
    name: str
    category: str
    cost: float
    risk_reduction_pct: float
    loss_reduction_pct: float
    affected_asset_types: List[str]
    description: str
    implementation_time_weeks: int
    loss_avoided: Optional[float] = None
    score_drop: Optional[float] = None
    roi: Optional[float] = None

# ==============================================================================
# OPTIMIZATION & WHAT-IF SIMULATION SCHEMAS
# ==============================================================================

class OptimizationRequest(BaseModel):
    budget: float = Field(500000.0, ge=10000.0, example=500000.0, description="Available security capital in INR")

class SimulationRequest(BaseModel):
    threat_multiplier: float = Field(1.0, ge=0.1, le=5.0, example=1.0)
    asset_value_multiplier: float = Field(1.0, ge=0.1, le=5.0, example=1.0)
    cvss_multiplier: float = Field(1.0, ge=0.1, le=2.0, example=1.0)
    enabled_control_ids: List[int] = Field(default_factory=list)

class MonteCarloRequest(BaseModel):
    iterations: int = Field(10000, ge=1000, le=50000, example=10000, description="Probabilistic simulation trials")
    confidence_level: float = Field(0.95, ge=0.80, le=0.99, example=0.95)
    enabled_control_ids: List[int] = Field(default_factory=list)

# ==============================================================================
# WEBSITE SCANNER SCHEMAS
# ==============================================================================

class WebsiteScanRequest(BaseModel):
    url: str = Field(..., example="https://example.com", description="Target domain or URL to audit")

# ==============================================================================
# GENERIC & BULK IMPORT/EXPORT SCHEMAS
# ==============================================================================

class GenericMessageResponse(BaseModel):
    success: bool
    message: str
    details: Optional[Any] = None

class BulkImportRequest(BaseModel):
    entity_type: str = Field(..., example="assets", description="assets, vulnerabilities, or controls")
    items: List[Dict[str, Any]]

