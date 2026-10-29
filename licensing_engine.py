# -*- coding: utf-8 -*-
import os
import json
import base64
import hashlib
import hmac
from datetime import datetime, timedelta

# Asymmetric Ed25519 Keys
# The Vendor Hub holds the PRIVATE KEY exclusively for signing licenses.
# Client apps only possess the PUBLIC KEY for verification.
ED25519_PRIVATE_KEY_B64 = "xB3A4L+WausHrkue1AuA7j5PqniG3eddO+I8MKGJqrA="
ED25519_PUBLIC_KEY_B64 = "GMGx6MuvR9wExI3VAp46IbEfPOLHveZkfMoC5ryZLbU="

# Legacy HMAC key for backward compatibility fallback
LEGACY_HMAC_SECRET = "LAW-OFFICE-SYS-MASTER-SIG-2026-FIRM-SECURE-KEY-v1"

def generate_signed_license(
    machine_id: str,
    client_name: str = "مكتب محاماة",
    license_type: str = "FULL",
    duration_type: str = "LIFETIME",
    custom_days: int = None,
    max_cases: int = None,
    max_lawyers: int = None,
    max_staff: int = None
) -> tuple:
    """
    Generates a cryptographically signed license token.
    Returns: (token_str, expires_at_str, payload_dict)
    """
    mid = machine_id.strip().upper()
    lic_type = license_type.upper()
    
    expires_at = None
    now_dt = datetime.now()
    
    # Calculate expiration based on duration_type
    dur = duration_type.upper()
    if dur == "LIFETIME":
        expires_at = None
    elif dur == "YEARLY" or dur == "1_YEAR":
        expires_at = (now_dt + timedelta(days=365)).strftime("%Y-%m-%d 23:59:59")
    elif dur == "90_DAYS" or dur == "3_MONTHS":
        expires_at = (now_dt + timedelta(days=90)).strftime("%Y-%m-%d 23:59:59")
    elif dur == "60_DAYS" or dur == "2_MONTHS":
        expires_at = (now_dt + timedelta(days=60)).strftime("%Y-%m-%d 23:59:59")
    elif dur == "MONTHLY" or dur == "30_DAYS":
        expires_at = (now_dt + timedelta(days=30)).strftime("%Y-%m-%d 23:59:59")
    elif dur == "CUSTOM" and custom_days:
        expires_at = (now_dt + timedelta(days=int(custom_days))).strftime("%Y-%m-%d 23:59:59")

    # Set edition-specific default caps if not explicitly overridden
    if lic_type in ["STARTER", "STARTER_EDITION"]:
        if max_cases is None:
            max_cases = 20
        if max_lawyers is None:
            max_lawyers = 4
        if max_staff is None:
            max_staff = 2
    elif lic_type == "LITE":
        if max_cases is None:
            max_cases = 100

    payload = {
        "machine_id": mid,
        "client_name": client_name.strip(),
        "license_type": lic_type,
        "created_at": now_dt.strftime("%Y-%m-%d %H:%M:%S")
    }

    if lic_type in ["STARTER", "STARTER_EDITION"]:
        payload["max_trainees"] = 1
        payload["max_associates"] = 2
        payload["team_breakdown"] = "صاحب المكتب + 2 محامين + محامٍ تحت التدريب + 2 موظفين إداريين"

    if expires_at:
        payload["expires_at"] = expires_at
    if max_cases is not None:
        payload["max_cases"] = max_cases
    if max_lawyers is not None:
        payload["max_lawyers"] = max_lawyers
    if max_staff is not None:
        payload["max_staff"] = max_staff

    # Pack and sign (Asymmetric Ed25519 preferred)
    b64_payload = base64.urlsafe_b64encode(json.dumps(payload).encode('utf-8')).decode('utf-8')
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
        priv_bytes = base64.b64decode(ED25519_PRIVATE_KEY_B64)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig_raw = private_key.sign(b64_payload.encode('utf-8'))
        sig = base64.urlsafe_b64encode(sig_raw).decode('utf-8')
    except Exception:
        # Fallback to HMAC-SHA256
        sig = hmac.new(LEGACY_HMAC_SECRET.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()

    token = f"{b64_payload}.{sig}"
    return token, expires_at, payload

def verify_token(token: str) -> tuple:
    """Verifies a token string and returns (is_valid, payload, error)"""
    if not token or "." not in token:
        return False, None, "رمز الترخيص غير مكتمل أو غير صالح"

    try:
        b64_payload, signature = token.strip().split(".", 1)

        # 1. Asymmetric Ed25519 verification first
        is_sig_valid = False
        try:
            from cryptography.hazmat.primitives.asymmetric import ed25519
            pub_bytes = base64.b64decode(ED25519_PUBLIC_KEY_B64)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = base64.urlsafe_b64decode(signature.encode('utf-8'))
            public_key.verify(sig_bytes, b64_payload.encode('utf-8'))
            is_sig_valid = True
        except Exception:
            pass

        # 2. Fallback to legacy HMAC verification
        if not is_sig_valid:
            expected_sig = hmac.new(LEGACY_HMAC_SECRET.encode('utf-8'), b64_payload.encode('utf-8'), hashlib.sha256).hexdigest()
            if hmac.compare_digest(signature, expected_sig):
                is_sig_valid = True

        if not is_sig_valid:
            return False, None, "توقيع الترخيص الرقمي غير متطابق (تم التلاعب به)"

        payload_bytes = base64.urlsafe_b64decode(b64_payload.encode('utf-8'))
        payload = json.loads(payload_bytes.decode('utf-8'))
        return True, payload, "الترخيص سليم وموثق"
    except Exception as e:
        return False, None, str(e)
