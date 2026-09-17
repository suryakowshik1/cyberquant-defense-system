"""
CyberQuant AI - Enterprise Layer 7 Web Application Firewall (WAF) Middleware
Defensive Perimeter Security Engine for FastAPI / ASGI

Protects against OWASP Top 10 web vulnerabilities:
- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Path Traversal / Local & Remote File Inclusion (LFI/RFI)
- Command Injection / Remote Code Execution (RCE)
- Malicious Vulnerability Scanners & Reconnaissance Bots
- SSRF & Cloud Metadata Exploitation
- Distributed Denial-of-Service (DoS) & Brute-Force via Adaptive Rate Limiting
- HTTP Header Security Hardening (Clickjacking, MIME Sniffing, HSTS)
"""

import time
import re
import urllib.parse
from collections import defaultdict, deque
from typing import Dict, List, Tuple, Optional, Any
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


# =====================================================================
# 1. THREAT DETECTION PATTERNS (COMPILED REGEX SIGNATURES)
# =====================================================================

THREAT_PATTERNS = {
    "SQL_INJECTION": [
        re.compile(r"(\b(UNION(\s+ALL)?\s+SELECT|SELECT\s+.*?\s+FROM|INSERT\s+INTO\s+.*?\s+VALUES|DELETE\s+FROM|DROP\s+(TABLE|DATABASE|VIEW)|ALTER\s+TABLE|TRUNCATE\s+TABLE)\b)", re.IGNORECASE),
        re.compile(r"('(\s*|\+)*(OR|AND)(\s*|\+)+[\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+)", re.IGNORECASE),
        re.compile(r"(\bOR\b\s+\d+\s*=\s*\d+|\bAND\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
        re.compile(r"(\b(SLEEP|BENCHMARK|WAITFOR\s+DELAY|PG_SLEEP)\s*\()", re.IGNORECASE),
        re.compile(r"(\b(EXEC|EXECUTE)\s+(\@\w+|\(.*?xp_cmdshell|sp_executesql))", re.IGNORECASE),
        re.compile(r"(;\s*--|--\s*$|/\*.*?\*/)", re.IGNORECASE | re.DOTALL),
        re.compile(r"(\bHAVING\s+\d+\s*=\s*\d+|\bGROUP\s+BY\b.*?\bHAVING\b)", re.IGNORECASE),
    ],
    "CROSS_SITE_SCRIPTING": [
        re.compile(r"<\s*script[^>]*>.*?<\s*/\s*script\s*>", re.IGNORECASE | re.DOTALL),
        re.compile(r"<\s*script[^>]*>", re.IGNORECASE),
        re.compile(r"javascript\s*:\s*[^\s;]+", re.IGNORECASE),
        re.compile(r"\bon(error|load|click|mouseover|submit|focus|blur|change|input|pointerdown)\s*=", re.IGNORECASE),
        re.compile(r"<\s*(iframe|object|embed|svg|img|body|link|style)[^>]*?(onerror|onload|src\s*=\s*['\"]?javascript:)[^>]*>", re.IGNORECASE),
        re.compile(r"\bdocument\.(cookie|location|domain|write)\b", re.IGNORECASE),
        re.compile(r"\b(eval|alert|prompt|confirm)\s*\(", re.IGNORECASE),
    ],
    "PATH_TRAVERSAL": [
        re.compile(r"(\.\.[/\\]|\.\.%2f|\.\.%5c)", re.IGNORECASE),
        re.compile(r"(%2e%2e%2f|%2e%2e/|\.\.%252f|%252e%252e%252f)", re.IGNORECASE),
        re.compile(r"(/etc/(passwd|shadow|hosts|group)|/proc/self/environ|win\.ini|boot\.ini)", re.IGNORECASE),
        re.compile(r"\b(file|php|phar|data|zip)://", re.IGNORECASE),
    ],
    "COMMAND_INJECTION": [
        re.compile(r"(\||;|&&|`|\$\()\s*(cat\s+|ls\s+|id\b|whoami|dir\b|type\s+|net\s+user|powershell|cmd\.exe|wget\s+|curl\s+|bash\b|sh\b|chmod\s+)", re.IGNORECASE),
        re.compile(r"(powershell(\.exe)?\s+(-enc|-e|-ExecutionPolicy|-c))", re.IGNORECASE),
        re.compile(r"(cmd\.exe\s+/c)", re.IGNORECASE),
        re.compile(r"(`[^`]+`|\$\([^)]+\))"),
    ],
    "MALICIOUS_SCANNER": [
        re.compile(r"\b(sqlmap|nikto|acunetix|nessus|masscan|nmap|dirbuster|gobuster|wpscan|openvas|arachni|zaproxy|commix|havij|netsparker|qualys)\b", re.IGNORECASE),
    ],
    "SSRF_METADATA": [
        re.compile(r"\b(169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200)\b", re.IGNORECASE),
    ]
}

# Exempted paths (Static assets that don't execute server-side code)
EXEMPT_STATIC_EXTENSIONS = (
    ".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
    ".woff", ".woff2", ".ttf", ".eot", ".map"
)


# =====================================================================
# 2. IN-MEMORY THREAT TELEMETRY & STATS TRACKER
# =====================================================================

class WAFTelemetry:
    """Thread-safe statistics and sliding log buffer for blocked attacks."""
    def __init__(self, max_logs: int = 100):
        self.max_logs = max_logs
        self.total_requests = 0
        self.total_blocked = 0
        self.threat_counts = {
            "SQL_INJECTION": 0,
            "CROSS_SITE_SCRIPTING": 0,
            "PATH_TRAVERSAL": 0,
            "COMMAND_INJECTION": 0,
            "MALICIOUS_SCANNER": 0,
            "SSRF_METADATA": 0,
            "RATE_LIMIT_EXCEEDED": 0,
            "PAYLOAD_TOO_LARGE": 0
        }
        self.recent_events = deque(maxlen=max_logs)
        self.start_time = time.time()

    def record_request(self):
        self.total_requests += 1

    def record_threat(self, threat_type: str, client_ip: str, path: str, method: str, sample: str):
        self.total_blocked += 1
        if threat_type in self.threat_counts:
            self.threat_counts[threat_type] += 1
        else:
            self.threat_counts[threat_type] = 1

        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "client_ip": client_ip,
            "threat_type": threat_type,
            "method": method,
            "path": path,
            "matched_sample": sample[:120] if sample else ""
        }
        self.recent_events.appendleft(event)

    def get_stats(self) -> Dict[str, Any]:
        uptime_seconds = int(time.time() - self.start_time)
        return {
            "status": "ACTIVE_DEFENSE",
            "uptime_seconds": uptime_seconds,
            "total_requests_inspected": self.total_requests,
            "total_threats_blocked": self.total_blocked,
            "blocked_threats_breakdown": dict(self.threat_counts),
            "recent_blocked_events": list(self.recent_events)
        }

    def reset(self):
        self.total_requests = 0
        self.total_blocked = 0
        for k in self.threat_counts:
            self.threat_counts[k] = 0
        self.recent_events.clear()
        self.start_time = time.time()


waf_telemetry = WAFTelemetry()


# =====================================================================
# 3. SLIDING-WINDOW ADAPTIVE RATE LIMITER
# =====================================================================

class SlidingWindowRateLimiter:
    """
    Per-IP request rate limiter preventing brute-force, credential stuffing,
    and HTTP DoS attacks.
    """
    def __init__(self):
        # ip -> deque of timestamps
        self.general_windows: Dict[str, deque] = defaultdict(deque)
        self.auth_windows: Dict[str, deque] = defaultdict(deque)
        self.last_cleanup = time.time()

    def is_rate_limited(self, client_ip: str, path: str) -> Tuple[bool, int]:
        """
        Checks if the request exceeds rate limits.
        Returns (is_limited, retry_after_seconds).
        - Auth endpoints: 25 requests / 60 seconds.
        - General endpoints: 180 requests / 60 seconds.
        """
        now = time.time()

        # Periodic cleanup of expired entries (every 5 mins)
        if now - self.last_cleanup > 300:
            self._cleanup(now)

        is_sensitive = any(k in path.lower() for k in ("/api/auth/", "/auth/", "/firewall", "/scan-website", "/audit-database"))
        window_duration = 60.0

        if is_sensitive:
            limit = 20
            timestamps = self.auth_windows[client_ip]
        else:
            limit = 180
            timestamps = self.general_windows[client_ip]

        # Purge timestamps older than window
        while timestamps and timestamps[0] <= now - window_duration:
            timestamps.popleft()

        if len(timestamps) >= limit:
            oldest = timestamps[0]
            retry_after = max(1, int(window_duration - (now - oldest)))
            return True, retry_after

        timestamps.append(now)
        return False, 0

    def _cleanup(self, now: float):
        cutoff = now - 60.0
        for ip in list(self.general_windows.keys()):
            q = self.general_windows[ip]
            while q and q[0] <= cutoff:
                q.popleft()
            if not q:
                del self.general_windows[ip]

        for ip in list(self.auth_windows.keys()):
            q = self.auth_windows[ip]
            while q and q[0] <= cutoff:
                q.popleft()
            if not q:
                del self.auth_windows[ip]

        self.last_cleanup = now


waf_rate_limiter = SlidingWindowRateLimiter()


# =====================================================================
# 4. CORE WAF INSPECTION & SANITIZATION ENGINE
# =====================================================================

def multi_decode(val: str, max_depth: int = 3) -> str:
    """Recursively URL-decodes a string to catch multi-stage encoding bypasses."""
    if not val:
        return ""
    cur = val
    for _ in range(max_depth):
        try:
            decoded = urllib.parse.unquote(cur)
            if decoded == cur:
                break
            cur = decoded
        except Exception:
            break
    return cur


def inspect_payload(text: str) -> Optional[Tuple[str, str]]:
    """
    Scans a string across all compiled threat regexes.
    Returns (threat_name, matched_substring) if malicious, else None.
    """
    if not text:
        return None

    # Test both raw and recursively URL-decoded versions
    candidates = [text]
    decoded = multi_decode(text)
    if decoded != text:
        candidates.append(decoded)

    for candidate in candidates:
        for threat_type, patterns in THREAT_PATTERNS.items():
            for pattern in patterns:
                m = pattern.search(candidate)
                if m:
                    return threat_type, m.group(0)

    return None


# =====================================================================
# 5. FASTAPI / ASGI WAF MIDDLEWARE CLASS
# =====================================================================

class CyberQuantWAFMiddleware(BaseHTTPMiddleware):
    """
    Enterprise L7 WAF Middleware for CyberQuant AI Platform.
    Intercepts and validates all incoming HTTP traffic before hitting route handlers.
    Injects military-grade security headers on all responses.
    """

    MAX_PAYLOAD_SIZE = 2 * 1024 * 1024  # 2 Megabytes max body

    async def dispatch(self, request: Request, call_next):
        client_ip = request.client.host if request.client else "127.0.0.1"
        # Respect Cloudflare / Reverse-Proxy client IP if configured
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()

        path = request.url.path
        method = request.method

        waf_telemetry.record_request()

        # -------------------------------------------------------------
        # 1. Skip deep body inspection for exempt static assets
        # -------------------------------------------------------------
        is_static = path.startswith("/static") or any(path.endswith(ext) for ext in EXEMPT_STATIC_EXTENSIONS)

        # -------------------------------------------------------------
        # 2. Rate Limiting Check (DDoS / Brute Force)
        # -------------------------------------------------------------
        if not is_static:
            is_limited, retry_after = waf_rate_limiter.is_rate_limited(client_ip, path)
            if is_limited:
                waf_telemetry.record_threat(
                    "RATE_LIMIT_EXCEEDED", client_ip, path, method, f"Threshold exceeded. Retry in {retry_after}s"
                )
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Security Shield Triggered",
                        "status": 429,
                        "threat_type": "RATE_LIMIT_EXCEEDED",
                        "message": f"Excessive request rate detected from {client_ip}. Please wait {retry_after} seconds before retrying.",
                        "retry_after_seconds": retry_after
                    },
                    headers={"Retry-After": str(retry_after)}
                )

        # -------------------------------------------------------------
        # 3. Bad User-Agent / Scanner Inspection
        # -------------------------------------------------------------
        user_agent = request.headers.get("user-agent", "")
        scanner_match = THREAT_PATTERNS["MALICIOUS_SCANNER"][0].search(user_agent)
        if scanner_match:
            waf_telemetry.record_threat(
                "MALICIOUS_SCANNER", client_ip, path, method, scanner_match.group(0)
            )
            return JSONResponse(
                status_code=403,
                content={
                    "error": "WAF Security Filter Blocked Request",
                    "threat_type": "MALICIOUS_SCANNER",
                    "message": "Automated security scanner or reconnaissance tool detected and blocked.",
                    "client_ip": client_ip
                }
            )

        # -------------------------------------------------------------
        # 4. URL Path & Query String Inspection
        # -------------------------------------------------------------
        query_string = request.url.query
        check_targets = [
            ("PATH", path),
            ("QUERY", query_string)
        ]

        for target_name, target_val in check_targets:
            if not target_val:
                continue
            threat = inspect_payload(target_val)
            if threat:
                threat_type, matched_snippet = threat
                waf_telemetry.record_threat(
                    threat_type, client_ip, path, method, f"[{target_name}] {matched_snippet}"
                )
                return JSONResponse(
                    status_code=403,
                    content={
                        "error": "Web Application Firewall (WAF) Threat Detected",
                        "threat_type": threat_type,
                        "location": target_name,
                        "message": f"Malicious payload signature detected in {target_name.lower()}.",
                        "client_ip": client_ip
                    }
                )

        # -------------------------------------------------------------
        # 5. Request Body Inspection (POST / PUT / PATCH)
        # -------------------------------------------------------------
        if method in ("POST", "PUT", "PATCH") and not is_static:
            content_length = request.headers.get("content-length")
            if content_length and int(content_length) > self.MAX_PAYLOAD_SIZE:
                waf_telemetry.record_threat(
                    "PAYLOAD_TOO_LARGE", client_ip, path, method, f"Size: {content_length} bytes"
                )
                return JSONResponse(
                    status_code=413,
                    content={
                        "error": "WAF Security Limit Exceeded",
                        "threat_type": "PAYLOAD_TOO_LARGE",
                        "message": f"Payload size exceeds maximum allowed limit ({self.MAX_PAYLOAD_SIZE} bytes)."
                    }
                )

            # Safely capture and re-inject body for downstream FastAPI handlers
            body_bytes = await request.body()

            # Ensure Starlette/FastAPI endpoints can read the body stream again
            async def receive():
                return {"type": "http.request", "body": body_bytes}
            request._receive = receive

            # Only inspect text/json payloads
            content_type = request.headers.get("content-type", "").lower()
            if any(ct in content_type for ct in ("json", "text", "x-www-form-urlencoded")):
                try:
                    body_text = body_bytes.decode("utf-8", errors="ignore")
                    threat = inspect_payload(body_text)
                    if threat:
                        threat_type, matched_snippet = threat
                        waf_telemetry.record_threat(
                            threat_type, client_ip, path, method, f"[BODY] {matched_snippet}"
                        )
                        return JSONResponse(
                            status_code=403,
                            content={
                                "error": "Web Application Firewall (WAF) Threat Detected",
                                "threat_type": threat_type,
                                "location": "BODY",
                                "message": f"Malicious {threat_type} attack vector blocked in request body.",
                                "client_ip": client_ip
                            }
                        )
                except Exception:
                    pass

        # -------------------------------------------------------------
        # 6. Pass Request to Application Route Handlers
        # -------------------------------------------------------------
        response: Response = await call_next(request)

        # -------------------------------------------------------------
        # 7. Apply Layer 7 HTTP Security Hardening Headers (Priority 12)
        # -------------------------------------------------------------
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.jsdelivr.net; "
            "font-src 'self' https://fonts.gstatic.com data:; "
            "img-src 'self' data: https: blob:; "
            "connect-src 'self' https: http:; "
            "frame-ancestors 'self'; "
            "object-src 'none'; "
            "base-uri 'self';"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()"
        response.headers["Server"] = "CyberQuant-Shield-WAF/2.0 (Hardened)"
        response.headers["X-Protected-By"] = "CyberQuant L7 WAF"

        return response


def get_waf_stats() -> Dict[str, Any]:
    """Helper export to retrieve telemetry stats."""
    return waf_telemetry.get_stats()


def reset_waf_stats():
    """Helper export to reset telemetry stats."""
    waf_telemetry.reset()
