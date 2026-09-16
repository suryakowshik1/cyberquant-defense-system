"""
CyberQuant AI - Multi-Factor Authentication & OTP Service
Handles secure OTP generation, verification, and email dispatch for administrative password recovery.
Authorized Administrators: pavansaikumar5616@gmail.com, suryakowshik8@gmail.com
"""
import os
import time
import random
import hashlib
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from app.database import get_db_connection

def load_env_file():
    """Loads environment variables from .env file if present."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env_path = os.path.join(base_dir, ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k and k not in os.environ:
                            os.environ[k] = v
        except Exception as e:
            print(f"[ENV NOTICE] Could not read .env: {e}")

load_env_file()

AUTHORIZED_EMAILS = [
    "pavansaikumar5616@gmail.com",
    "suryakowshik8@gmail.com",
    "cyberquant26@gmail.com",
    "admin@cyberquant.local"
]

# Fast in-memory cache for OTPs to guarantee resilience across serverless container environments
ACTIVE_OTPS = {}

def generate_and_store_otp(email: str) -> dict:
    """
    Generates a secure 6-digit OTP, stores it in SQLite and memory with a 10-minute expiry,
    and attempts email delivery.
    """
    clean_email = email.strip().lower()
    # Permit authorized emails or any valid email address
    if clean_email not in [e.lower() for e in AUTHORIZED_EMAILS] and "@" not in clean_email:
        return {
            "success": False,
            "message": "Invalid or unauthorized email address. Please enter a valid email."
        }
    
    # Generate 6-digit random code
    otp_code = f"{random.randint(100000, 999999)}"
    now = time.time()
    expires_at = now + 600.0  # 10 minutes

    # Store in fast in-memory cache
    ACTIVE_OTPS[clean_email] = {
        "code": otp_code,
        "expires_at": expires_at,
        "used": False
    }

    # Store in SQLite DB
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE password_resets SET used = 1 WHERE email = ? AND used = 0", (clean_email,))
        c.execute("""
        INSERT INTO password_resets (email, otp_code, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        """, (clean_email, otp_code, expires_at, now))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB NOTICE] OTP SQLite persistence notice: {e}")

    # Attempt email dispatch via SMTP
    delivery_info = dispatch_otp_email(clean_email, otp_code)
    email_sent = delivery_info.get("sent", False)
    
    print(f"\n===========================================================")
    print(f" [AUTH OTP DISPATCH] Recovery Email: {clean_email}")
    print(f" [AUTH OTP CODE]     >>> {otp_code} <<< (Valid for 10 min)")
    print(f" [EMAIL SENT VIA SMTP] {email_sent} ({delivery_info.get('mode')})")
    print(f"===========================================================\n")

    return {
        "success": True,
        "message": f"A 6-digit verification code has been dispatched to {clean_email}. Please check your inbox and spam folder.",
        "email": clean_email,
        "expires_in_seconds": 600,
        "delivery_mode": delivery_info.get("mode", "smtp" if email_sent else "pending_smtp"),
        "email_sent": email_sent
    }


def verify_otp_code(email: str, otp_code: str, mark_used: bool = True) -> dict:
    """
    Verifies if the supplied OTP matches the active code in memory or database and is unexpired.
    Optionally marks the code as used (default True).
    """
    clean_email = email.strip().lower()
    clean_code = otp_code.strip()
    now = time.time()

    # 1. Check in-memory cache first (instant & reliable)
    if clean_email in ACTIVE_OTPS:
        rec = ACTIVE_OTPS[clean_email]
        if rec["code"] == clean_code:
            if now <= rec["expires_at"]:
                if mark_used:
                    rec["used"] = True
                return {"valid": True, "message": "OTP matched and verified successfully."}
            else:
                return {"valid": False, "message": "Verification OTP has expired. Please request a fresh code."}

    # 2. Check SQLite DB
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        SELECT id, otp_code, expires_at, used FROM password_resets
        WHERE LOWER(email) = ? AND used = 0
        ORDER BY id DESC LIMIT 1
        """, (clean_email,))
        record = c.fetchone()

        if not record:
            conn.close()
            return {"valid": False, "message": "No active OTP request found for this email. Please request a new code."}

        if record["otp_code"] != clean_code:
            conn.close()
            return {"valid": False, "message": "Incorrect verification OTP. The code does not match."}

        if now > record["expires_at"]:
            conn.close()
            return {"valid": False, "message": "Verification OTP has expired. Please request a fresh code."}

        if mark_used:
            c.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (record["id"],))
            conn.commit()
        conn.close()

        return {"valid": True, "message": "OTP matched and verified successfully."}
    except Exception as e:
        return {"valid": False, "message": f"Verification error: {str(e)}"}


def dispatch_otp_email(recipient_email: str, otp_code: str) -> dict:
    """
    Dispatches an HTML formatted email if SMTP environment variables are configured.
    Falls back gracefully if SMTP is not configured or fails.
    """
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com") or "smtp.gmail.com"
    smtp_port = int(os.getenv("SMTP_PORT", "587") or "587")
    smtp_user = os.getenv("SMTP_USER", "cyberquant26@gmail.com").strip() or "cyberquant26@gmail.com"
    smtp_pass = (os.getenv("SMTP_PASS") or "zffzpemfpvfxdvdg").replace(" ", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "CyberQuant SOC Defense <cyberquant26@gmail.com>").strip() or "cyberquant26@gmail.com"

    if not smtp_user or not smtp_pass:
        return {"sent": False, "mode": "simulated", "note": "SMTP_USER or SMTP_PASS not set in environment."}

    try:
        subject = f"🔐 CyberQuant AI - Security Password Reset OTP: {otp_code}"
        html_body = f"""
        <html>
        <body style="font-family: Arial, sans-serif; background-color: #0b0f19; color: #f3f4f6; padding: 25px;">
            <div style="background-color: #111827; border: 1px solid #06b6d4; border-radius: 12px; padding: 24px; max-width: 520px; margin: 0 auto;">
                <h2 style="color: #06b6d4; margin-top: 0; font-size: 20px;">🛡️ CYBERQUANT AI - SOC DEFENSE</h2>
                <p style="font-size: 14px; color: #d1d5db; line-height: 1.5;">
                    An administrative password reset or authentication request was initiated for your Cyber Risk account.
                </p>
                <div style="background-color: #0b0f19; border: 1px dashed #10b981; border-radius: 8px; padding: 18px; text-align: center; margin: 20px 0;">
                    <div style="font-size: 12px; color: #9ca3af; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 6px;">ONE-TIME VERIFICATION CODE</div>
                    <div style="font-size: 36px; font-weight: bold; color: #10b981; letter-spacing: 8px; font-family: monospace;">{otp_code}</div>
                </div>
                <p style="font-size: 13px; color: #9ca3af; line-height: 1.4;">
                    ⏳ <strong>Validity:</strong> This OTP is strictly valid for <strong>10 minutes</strong>.<br>
                    🔒 <strong>Notice:</strong> If you did not initiate this request, please contact your security response team immediately.
                </p>
                <div style="border-top: 1px solid #1f2937; margin-top: 20px; padding-top: 12px; font-size: 11px; color: #6b7280; text-align: center;">
                    Continuous Cyber Risk Quantification & Security Investment Platform
                </div>
            </div>
        </body>
        </html>
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = recipient_email
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=8) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_from, recipient_email, msg.as_string())
            return {"sent": True, "mode": "smtp_tls"}
        except Exception as err_tls:
            print(f"[SMTP TLS NOTICE] Port {smtp_port} failed ({err_tls}), attempting SSL port 465...")
            with smtplib.SMTP_SSL(smtp_host, 465, timeout=8) as server_ssl:
                server_ssl.login(smtp_user, smtp_pass)
                server_ssl.sendmail(smtp_from, recipient_email, msg.as_string())
            return {"sent": True, "mode": "smtp_ssl"}
    except Exception as e:
        print(f"[SMTP WARNING] Failed to deliver live email via SMTP: {e}")
        return {"sent": False, "mode": "simulated", "error": str(e)}


# Fast runtime cache for active firewall passcode resets
ACTIVE_FIREWALL_RESETS = {}

def dispatch_firewall_reset_email(recipient_email: str, reset_link: str, otp_code: str) -> dict:
    """
    Dispatches a dedicated HTML email with a direct one-click reset link and verification code
    for changing the Master Firewall Passcode.
    """
    smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com") or "smtp.gmail.com"
    smtp_port = int(os.getenv("SMTP_PORT", "587") or "587")
    smtp_user = os.getenv("SMTP_USER", "cyberquant26@gmail.com").strip() or "cyberquant26@gmail.com"
    smtp_pass = (os.getenv("SMTP_PASS") or "zffzpemfpvfxdvdg").replace(" ", "").strip()
    smtp_from = os.getenv("SMTP_FROM", "CyberQuant SOC Defense <cyberquant26@gmail.com>").strip() or "cyberquant26@gmail.com"

    if not smtp_user or not smtp_pass:
        return {"sent": False, "mode": "simulated", "note": "SMTP credentials not configured."}

    try:
        subject = "🛡️ CyberQuant AI - Master Firewall Passcode Reset Link"
        html_body = f"""
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0b0f19; color: #f3f4f6; padding: 25px;">
            <div style="background-color: #111827; border: 1px solid #10b981; border-radius: 14px; padding: 28px; max-width: 520px; margin: 0 auto; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
                <div style="text-align: center; margin-bottom: 20px;">
                    <div style="display: inline-block; padding: 12px; background: rgba(16, 185, 129, 0.15); border: 1px solid #10b981; border-radius: 12px;">
                        <span style="font-size: 28px;">🛡️</span>
                    </div>
                    <h2 style="color: #10b981; margin: 12px 0 4px 0; font-size: 20px; letter-spacing: 1px;">CYBERQUANT AI DEFENSE</h2>
                    <div style="font-size: 11px; color: #9ca3af; text-transform: uppercase; letter-spacing: 1.5px;">Master Firewall Clearance Console</div>
                </div>

                <p style="font-size: 14px; color: #d1d5db; line-height: 1.6; margin-bottom: 20px;">
                    A request was received to <strong>change or reset the Master Firewall Passcode</strong> for your perimeter defense console.
                </p>

                <!-- One-Click Direct Reset Button -->
                <div style="text-align: center; margin: 26px 0;">
                    <a href="{reset_link}" target="_blank" style="background: linear-gradient(135deg, #10b981, #06b6d4); color: #ffffff; text-decoration: none; padding: 14px 28px; border-radius: 10px; font-weight: bold; font-size: 14px; letter-spacing: 0.8px; display: inline-block; box-shadow: 0 4px 20px rgba(16, 185, 129, 0.4);">
                        🔑 Click Here to Reset Master Passcode
                    </a>
                </div>

                <div style="text-align: center; margin: 16px 0; font-size: 12px; color: #9ca3af;">
                    — OR USE THIS 6-DIGIT AUTHORIZATION CODE —
                </div>

                <div style="background-color: #0b0f19; border: 1px dashed #10b981; border-radius: 8px; padding: 14px; text-align: center; margin: 12px 0;">
                    <div style="font-size: 30px; font-weight: bold; color: #10b981; letter-spacing: 6px; font-family: monospace;">{otp_code}</div>
                </div>

                <p style="font-size: 12px; color: #9ca3af; line-height: 1.5; margin-top: 22px;">
                    ⏳ <strong>Expiry:</strong> This reset link and verification code are strictly valid for <strong>15 minutes</strong>.<br>
                    ⚠️ <strong>Security Notice:</strong> If you did not request this master passcode reset, someone may be attempting to access your perimeter firewall controls. Review active SOC sessions immediately.
                </p>

                <div style="border-top: 1px solid #1f2937; margin-top: 22px; padding-top: 12px; font-size: 11px; color: #6b7280; text-align: center;">
                    CyberQuant Autonomous SOC & Continuous Perimeter Defense
                </div>
            </div>
        </body>
        </html>
        """
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = smtp_from
        msg["To"] = recipient_email
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=8) as server:
                server.starttls()
                server.login(smtp_user, smtp_pass)
                server.sendmail(smtp_from, recipient_email, msg.as_string())
            return {"sent": True, "mode": "smtp_tls"}
        except Exception as err_tls:
            print(f"[SMTP TLS NOTICE] Port {smtp_port} failed ({err_tls}), attempting SSL port 465...")
            with smtplib.SMTP_SSL(smtp_host, 465, timeout=8) as server_ssl:
                server_ssl.login(smtp_user, smtp_pass)
                server_ssl.sendmail(smtp_from, recipient_email, msg.as_string())
            return {"sent": True, "mode": "smtp_ssl"}
    except Exception as e:
        print(f"[SMTP FIREWALL RESET WARNING] {e}")
        return {"sent": False, "mode": "simulated", "error": str(e)}


def generate_firewall_reset(origin: str = "") -> dict:
    """
    Generates a secure reset token and OTP code, stores them, and dispatches an email
    to cyberquant26@gmail.com with the reset link.
    """
    recipient_email = "cyberquant26@gmail.com"
    token = hashlib.sha256(f"fw_{time.time()}_{random.random()}_{recipient_email}".encode()).hexdigest()[:32]
    otp_code = f"{random.randint(100000, 999999)}"
    now = time.time()
    expires_at = now + 900.0  # 15 minutes

    rec = {
        "token": token,
        "otp": otp_code,
        "email": recipient_email,
        "expires_at": expires_at,
        "used": False
    }
    ACTIVE_FIREWALL_RESETS[token] = rec
    ACTIVE_FIREWALL_RESETS[otp_code] = rec

    # Persist in SQLite
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        INSERT INTO password_resets (email, otp_code, expires_at, used, created_at)
        VALUES (?, ?, ?, 0, ?)
        """, (f"firewall_reset_{token}", otp_code, expires_at, now))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB FIREWALL RESET NOTICE] {e}")

    # Build reset link
    base_url = (origin or "").rstrip("/")
    if not base_url or not base_url.startswith("http"):
        base_url = os.getenv("APP_URL", "https://cyberquant-defense-system.vercel.app").rstrip("/")
    reset_link = f"{base_url}/?firewall_reset_token={token}"

    dispatch_res = dispatch_firewall_reset_email(recipient_email, reset_link, otp_code)
    email_sent = dispatch_res.get("sent", False)

    print(f"\n===========================================================")
    print(f" [FIREWALL RESET DISPATCH] Recipient: {recipient_email}")
    print(f" [RESET LINK]             >>> {reset_link} <<<")
    print(f" [VERIFICATION OTP CODE]  >>> {otp_code} <<<")
    print(f" [EMAIL SENT VIA SMTP]    {email_sent}")
    print(f"===========================================================\n")

    return {
        "success": True,
        "message": "A master passcode reset link and verification code have been dispatched to your administrator email.",
        "email_sent": email_sent,
        "expires_in_seconds": 900
    }

def verify_firewall_reset(token_or_otp: str) -> dict:
    """Verifies whether the reset token or OTP code is valid and unexpired."""
    clean = (token_or_otp or "").strip()
    if not clean:
        return {"valid": False, "message": "Authorization code or reset token is required."}

    now = time.time()
    if clean in ACTIVE_FIREWALL_RESETS:
        rec = ACTIVE_FIREWALL_RESETS[clean]
        if rec.get("used"):
            return {"valid": False, "message": "This reset authorization has already been used."}
        if now > rec.get("expires_at", 0):
            return {"valid": False, "message": "Reset authorization has expired. Please request a new link."}
        return {"valid": True, "message": "Token verified successfully."}

    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        SELECT id, expires_at, used FROM password_resets
        WHERE (otp_code = ? OR email = ?)
        ORDER BY id DESC LIMIT 1
        """, (clean, f"firewall_reset_{clean}"))
        row = c.fetchone()
        conn.close()
        if row:
            if row[2] == 1:
                return {"valid": False, "message": "This reset authorization has already been used."}
            if now > row[1]:
                return {"valid": False, "message": "Reset authorization has expired. Please request a new link."}
            return {"valid": True, "message": "Token verified successfully."}
    except Exception as e:
        print(f"[DB VERIFY RESET ERROR] {e}")

    return {"valid": False, "message": "Invalid authorization code or reset token."}

def consume_firewall_reset(token_or_otp: str):
    """Marks the firewall reset token or OTP as used."""
    clean = (token_or_otp or "").strip()
    if clean in ACTIVE_FIREWALL_RESETS:
        ACTIVE_FIREWALL_RESETS[clean]["used"] = True
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("""
        UPDATE password_resets SET used = 1 
        WHERE (otp_code = ? OR email = ?)
        """, (clean, f"firewall_reset_{clean}"))
        conn.commit()
        conn.close()
    except Exception:
        pass

