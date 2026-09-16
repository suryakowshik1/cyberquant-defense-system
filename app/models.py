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
    username: str = Field(..., min_length=1, max_length=100, description="Administrator username or authorized email")
    password: str = Field(..., min_length=1, max_length=256, description="User password")
    auth_vault: Optional[str] = Field(None, max_length=1024, description="Optional HMAC auth sync token")

class LoginResponse(BaseModel):
    success: bool
    username: str
    role: str
    token: str

class ForgotPasswordRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=150, description="Designated administrative recovery email")

class VerifyOtpRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=150)
    otp: str = Field(..., min_length=4, max_length=12)

class VerifyOtpSkipRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=150)
    otp: str = Field(..., min_length=4, max_length=12)

class ResetPasswordRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=150)
    otp: str = Field(..., min_length=4, max_length=12)
    new_password: str = Field(..., min_length=4, max_length=256)

class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=150, description="User email for OTP dispatch")
    username: str = Field(..., min_length=2, max_length=50, description="User requested username")
    password: str = Field(..., min_length=4, max_length=256, description="User requested password")

class RegisterVerifyRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=150)
    otp: str = Field(..., min_length=4, max_length=12)

class FirewallVerifyRequest(BaseModel):
    passcode: str = Field(..., min_length=1, max_length=64, description="Master firewall passcode")

class FirewallForgotRequest(BaseModel):
    origin: Optional[str] = Field(None, max_length=255, description="Client origin for email reset link")

class FirewallResetRequest(BaseModel):
    token_or_otp: str = Field(..., min_length=4, max_length=256, description="Passcode reset token or verification OTP")
    new_passcode: str = Field(..., min_length=4, max_length=64, description="New master firewall passcode")

# ==============================================================================
# ASSET MANAGEMENT SCHEMAS
# ==============================================================================

class AssetCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, example="Primary Transaction Database")
    asset_type: str = Field(..., min_length=1, max_length=100, example="Database")
    criticality: str = Field(..., min_length=1, max_length=50, example="Critical", description="Critical, High, Medium, or Low")
    asset_value: float = Field(..., gt=0, le=10_000_000_000.0, example=5000000.0, description="Replacement / business value in INR")
    data_sensitivity: str = Field(..., min_length=1, max_length=100, example="Confidential / PII")
    department: str = Field(..., min_length=1, max_length=100, example="Core Engineering and IT")
    internet_exposure: int = Field(1, ge=0, le=1, description="1 for internet-exposed, 0 for internal")
    exposure_factor: float = Field(0.75, ge=0.01, le=1.0, description="FAIR Exposure Factor percentage (0.01 - 1.0)")

class AssetUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    asset_type: Optional[str] = Field(None, min_length=1, max_length=100)
    criticality: Optional[str] = Field(None, min_length=1, max_length=50)
    asset_value: Optional[float] = Field(None, gt=0, le=10_000_000_000.0)
    data_sensitivity: Optional[str] = Field(None, min_length=1, max_length=100)
    department: Optional[str] = Field(None, min_length=1, max_length=100)
    internet_exposure: Optional[int] = Field(None, ge=0, le=1)
    exposure_factor: Optional[float] = Field(None, ge=0.01, le=1.0)

class AssetResponse(AssetCreate):
    id: int

# ==============================================================================
# VULNERABILITY MANAGEMENT SCHEMAS
# ==============================================================================

class VulnerabilityCreate(BaseModel):
    cve_id: str = Field(..., min_length=3, max_length=50, example="CVE-2024-3400")
    title: str = Field(..., min_length=1, max_length=250, example="Critical SQL Injection and Remote Code Execution in API")
    cvss_score: float = Field(..., ge=0.0, le=10.0, example=9.8)
    exploitability: float = Field(..., ge=0.0, le=1.0, example=0.90)
    asset_id: int = Field(..., gt=0)
    category: str = Field(..., min_length=1, max_length=100, example="Remote Code Execution")
    patch_available: int = Field(1, ge=0, le=1)
    exposure_level: str = Field("Public Internet", min_length=1, max_length=100, example="Public Internet")
    threat_likelihood: float = Field(0.50, ge=0.01, le=1.0, example=0.50)
    description: str = Field("", max_length=2000, example="Flaw in public API endpoints allowing unauthenticated RCE.")

class VulnerabilityUpdate(BaseModel):
    cve_id: Optional[str] = Field(None, min_length=3, max_length=50)
    title: Optional[str] = Field(None, min_length=1, max_length=250)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    exploitability: Optional[float] = Field(None, ge=0.0, le=1.0)
    asset_id: Optional[int] = Field(None, gt=0)
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    patch_available: Optional[int] = Field(None, ge=0, le=1)
    exposure_level: Optional[str] = Field(None, min_length=1, max_length=100)
    threat_likelihood: Optional[float] = Field(None, ge=0.01, le=1.0)
    description: Optional[str] = Field(None, max_length=2000)

class VulnerabilityResponse(VulnerabilityCreate):
    id: int

# ==============================================================================
# SECURITY CONTROLS & DEFENSIVE MITIGATION SCHEMAS
# ==============================================================================

class SecurityControlCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, example="Vulnerability Patching and Hotfix Automation")
    category: str = Field(..., min_length=1, max_length=100, example="Patch Management")
    cost: float = Field(..., ge=0, le=10_000_000_000.0, example=120000.0, description="Cost in INR")
    risk_reduction_pct: float = Field(..., ge=0, le=100.0, example=38.0)
    loss_reduction_pct: float = Field(..., ge=0, le=100.0, example=42.0)
    affected_asset_types: List[str] = Field(..., example=["Database", "Web Application"])
    description: str = Field(..., max_length=2000, example="Automated zero-day patch pipeline for critical RCE.")
    implementation_time_weeks: int = Field(..., ge=1, le=520, example=2)

class SecurityControlUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    cost: Optional[float] = Field(None, ge=0, le=10_000_000_000.0)
    risk_reduction_pct: Optional[float] = Field(None, ge=0, le=100.0)
    loss_reduction_pct: Optional[float] = Field(None, ge=0, le=100.0)
    affected_asset_types: Optional[List[str]] = None
    description: Optional[str] = Field(None, max_length=2000)
    implementation_time_weeks: Optional[int] = Field(None, ge=1, le=520)

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
    budget: float = Field(500000.0, ge=1000.0, le=10_000_000_000.0, example=500000.0, description="Available security capital in INR")

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
    url: str = Field(..., min_length=3, max_length=1000, example="https://example.com", description="Target domain or URL to audit")

# ==============================================================================
# GENERIC & BULK IMPORT/EXPORT SCHEMAS
# ==============================================================================

class GenericMessageResponse(BaseModel):
    success: bool
    message: str
    details: Optional[Any] = None

class BulkImportRequest(BaseModel):
    entity_type: str = Field(..., max_length=50, example="assets", description="assets, vulnerabilities, or controls")
    items: List[Dict[str, Any]]

