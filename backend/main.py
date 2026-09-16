from fastapi import FastAPI, UploadFile, File, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from pathlib import Path
from datetime import datetime
import base64
import hashlib
import hmac
import uuid
import json
import os
import secrets
import smtplib
import shutil
from email.message import EmailMessage

from services.static_analysis import analyze_file
from services.risk_service import (
    calculate_risk_score,
    get_risk_level,
    should_create_alert,
    get_risk_explanation
)
from services.report_service import (
    build_excel_report,
    build_pdf_report,
    generate_report,
)

# IMPORTANT:
# Real ML prediction using EMBER + Random Forest
from ml.model_service import predict_file


# ============================================================
# APPLICATION
# ============================================================

app = FastAPI(
    title="ThreatLens AI Backend",
    description="Malware Classification and Threat Detection System",
    version="1.0.0",
    openapi_tags=[
        {
            "name": "Authentication",
            "description": "User registration and authentication APIs"
        },
        {
            "name": "File Analysis",
            "description": "Malware file analysis and detection APIs"
        },
        {
            "name": "Detection",
            "description": "Detection history and classification APIs"
        },
        {
            "name": "Threat Monitoring",
            "description": "Threat monitoring, risk and alert APIs"
        },
        {
            "name": "Reports",
            "description": "Malware analysis reporting APIs"
        }
    ]
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DIRECTORIES
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

UPLOAD_DIR = BASE_DIR / "uploads"
STORAGE_DIR = BASE_DIR / "storage"

UPLOAD_DIR.mkdir(exist_ok=True)
STORAGE_DIR.mkdir(exist_ok=True)


# ============================================================
# DATABASE FILE
# ============================================================

DB_FILE = STORAGE_DIR / "db.json"
JWT_SECRET = os.environ.get(
    "THREATLENS_JWT_SECRET",
    "threatlens-local-development-secret-change-me"
)
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_SECONDS = 60 * 60 * 24


class SignUpRequest(BaseModel):
    name: str
    email: str
    password: str


class SignInRequest(BaseModel):
    email: str
    password: str


class ForgotPasswordRequest(BaseModel):
    email: str


class ResetPasswordRequest(BaseModel):
    token: str
    password: str


def load_db():

    if not DB_FILE.exists():

        return {
            "users": [],
            "detections": [],
            "alerts": [],
            "reports": []
        }

    try:

        with open(
            DB_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            return json.load(file)

    except Exception:

        return {
            "users": [],
            "detections": [],
            "alerts": [],
            "reports": []
        }


def save_db(db):

    with open(
        DB_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            db,
            file,
            indent=2,
            default=str
        )


def hash_password(password):

    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=16384,
        r=8,
        p=1
    )

    return "scrypt$16384$8$1${}${}".format(
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii")
    )


def verify_password(password, stored_hash):

    try:
        algorithm, n_value, r_value, p_value, encoded_salt, encoded_digest = (
            stored_hash.split("$", 5)
        )

        if algorithm != "scrypt":
            return False

        salt = base64.urlsafe_b64decode(encoded_salt.encode("ascii"))
        expected_digest = base64.urlsafe_b64decode(encoded_digest.encode("ascii"))
        actual_digest = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_value),
            r=int(r_value),
            p=int(p_value)
        )

        return hmac.compare_digest(actual_digest, expected_digest)
    except (ValueError, TypeError):
        return False


def encode_jwt(payload):

    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}

    def encode_part(value):
        return base64.urlsafe_b64encode(
            json.dumps(value, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")

    header_part = encode_part(header)
    payload_part = encode_part(payload)
    signing_input = f"{header_part}.{payload_part}".encode("ascii")
    signature = hmac.new(
        JWT_SECRET.encode("utf-8"),
        signing_input,
        hashlib.sha256
    ).digest()

    return f"{header_part}.{payload_part}." + base64.urlsafe_b64encode(
        signature
    ).rstrip(b"=").decode("ascii")


def decode_jwt(token):

    try:
        header_part, payload_part, signature_part = token.split(".", 2)
        signing_input = f"{header_part}.{payload_part}".encode("ascii")
        expected_signature = hmac.new(
            JWT_SECRET.encode("utf-8"),
            signing_input,
            hashlib.sha256
        ).digest()
        actual_signature = base64.urlsafe_b64decode(
            (signature_part + "=" * (-len(signature_part) % 4)).encode("ascii")
        )

        if not hmac.compare_digest(actual_signature, expected_signature):
            return None

        payload = json.loads(base64.urlsafe_b64decode(
            (payload_part + "=" * (-len(payload_part) % 4)).encode("ascii")
        ))

        if payload.get("exp", 0) < datetime.now().timestamp():
            return None

        return payload
    except (ValueError, TypeError, KeyError, json.JSONDecodeError):
        return None


def get_authenticated_user(authorization: str = Header(default="")):

    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")

    payload = decode_jwt(authorization[7:].strip())
    if not payload or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    users = load_db().get("users", [])
    user = next(
        (stored_user for stored_user in users if stored_user.get("email") == payload["sub"]),
        None
    )

    if not user:
        raise HTTPException(status_code=401, detail="User not found")

    return user


def send_password_reset_email(email, token):

    smtp_host = os.environ.get("THREATLENS_SMTP_HOST")
    smtp_user = os.environ.get("THREATLENS_SMTP_USER")
    smtp_password = os.environ.get("THREATLENS_SMTP_PASSWORD")
    smtp_from = os.environ.get("THREATLENS_SMTP_FROM", smtp_user)
    frontend_url = os.environ.get(
        "THREATLENS_FRONTEND_URL",
        "http://127.0.0.1:5173"
    )

    if not smtp_host or not smtp_from:
        raise RuntimeError("SMTP password-reset delivery is not configured")

    message = EmailMessage()
    message["Subject"] = "ThreatLens AI password reset"
    message["From"] = smtp_from
    message["To"] = email
    message.set_content(
        "Use this link to reset your ThreatLens AI password:\n\n"
        f"{frontend_url}/reset-password?token={token}\n\n"
        "This link expires in 30 minutes."
    )

    smtp_port = int(os.environ.get("THREATLENS_SMTP_PORT", "587"))
    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
        server.starttls()
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
        server.send_message(message)


# ============================================================
# ROOT
# ============================================================

@app.get(
    "/",
    tags=["Threat Monitoring"],
    summary="Get service status",
    description="Return the ThreatLens AI backend service status."
)
def root():

    return {
        "message": "ThreatLens AI Backend is running",
        "status": "success",
        "version": "1.0.0"
    }


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get(
    "/health",
    tags=["Threat Monitoring"],
    summary="Check backend health",
    description="Return the backend health status."
)
def health():

    return {
        "status": "healthy",
        "service": "ThreatLens AI Backend"
    }


# ============================================================
# AUTHENTICATION
# ============================================================

@app.post(
    "/api/auth/signup",
    status_code=201,
    tags=["Authentication"],
    summary="Register a user",
    description="Create a ThreatLens AI user account."
)
def signup(request: SignUpRequest):

    name = request.name.strip()
    email = request.email.strip().lower()

    if (
        not name
        or "@" not in email
        or not request.password
        or len(request.password) < 6
    ):
        raise HTTPException(
            status_code=400,
            detail="Name, email, and password are required"
        )

    db = load_db()
    users = db.setdefault("users", [])

    if any(user.get("email") == email for user in users):
        raise HTTPException(
            status_code=400,
            detail="An account with this email already exists"
        )

    user = {
        "id": str(uuid.uuid4()),
        "name": name,
        "email": email,
        "password_hash": hash_password(request.password)
    }
    users.append(user)
    save_db(db)

    return {
        "message": "User registered successfully",
        "user": {
            "name": user["name"],
            "email": user["email"]
        }
    }


@app.post(
    "/api/auth/signin",
    tags=["Authentication"],
    summary="Sign in a user",
    description="Verify credentials and issue a bearer access token."
)
def signin(request: SignInRequest):

    email = request.email.strip().lower()
    user = next(
        (
            stored_user
            for stored_user in load_db().get("users", [])
            if stored_user.get("email") == email
        ),
        None
    )

    if not user or not verify_password(
        request.password,
        user.get("password_hash", "")
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    now = int(datetime.now().timestamp())
    access_token = encode_jwt({
        "sub": user["email"],
        "iat": now,
        "exp": now + JWT_EXPIRY_SECONDS
    })

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "name": user["name"],
            "email": user["email"]
        }
    }


@app.get(
    "/api/auth/me",
    tags=["Authentication"],
    summary="Get the current user",
    description="Return the authenticated user's identity from a bearer token."
)
def current_user(authorization: str = Header(default="")):

    authenticated_user = get_authenticated_user(authorization)

    return {
        "name": authenticated_user["name"],
        "email": authenticated_user["email"]
    }


# ============================================================
# ANALYZE FILE
# ============================================================

@app.post(
    "/api/analyze",
    tags=["File Analysis"],
    summary="Analyze a malware sample",
    description="Run static analysis and ML classification for an uploaded file."
)
async def analyze_uploaded_file(
    file: UploadFile = File(...)
):

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename provided"
        )

    # --------------------------------------------------------
    # Generate unique ID
    # --------------------------------------------------------

    detection_id = str(uuid.uuid4())

    timestamp = datetime.now().isoformat()

    safe_filename = Path(
        file.filename
    ).name

    upload_path = (
        UPLOAD_DIR /
        f"{detection_id}_{safe_filename}"
    )

    # --------------------------------------------------------
    # Save uploaded file
    # --------------------------------------------------------

    try:

        with open(
            upload_path,
            "wb"
        ) as buffer:

            shutil.copyfileobj(
                file.file,
                buffer
            )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Failed to save file: {str(error)}"
        )

    # --------------------------------------------------------
    # STATIC ANALYSIS
    # --------------------------------------------------------

    try:

        static_result = analyze_file(
            str(upload_path)
        )

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=f"Static analysis failed: {str(error)}"
        )

    # --------------------------------------------------------
    # ML ANALYSIS
    # EMBER + RANDOM FOREST
    # --------------------------------------------------------

    ml_result = {
        "status": "not_available",
        "classification": "Unknown",
        "confidence": 0.0
    }

    try:

        # Only perform EMBER prediction for PE/EXE files
        is_pe = static_result.get(
            "pe_analysis",
            {}
        ).get(
            "is_pe",
            False
        )

        if is_pe:

            ml_result = predict_file(
                str(upload_path)
            )

        else:

            ml_result = {
                "status": "not_applicable",
                "classification": "Unknown",
                "confidence": 0.0,
                "message": (
                    "EMBER ML prediction is "
                    "available for PE executable files."
                )
            }

    except Exception as error:

        ml_result = {
            "status": "prediction_error",
            "classification": "Unknown",
            "confidence": 0.0,
            "error": str(error)
        }

    # --------------------------------------------------------
    # STATIC RISK SCORE
    # --------------------------------------------------------

    static_score = float(
        static_result.get(
            "static_risk_score",
            0
        )
    )

    # --------------------------------------------------------
    # FINAL RISK SCORE
    # --------------------------------------------------------

    final_score = calculate_risk_score(
        static_score,
        ml_result
    )

    risk_level = get_risk_level(
        final_score
    )

    # --------------------------------------------------------
    # FINAL CLASSIFICATION
    # --------------------------------------------------------

    ml_classification = ml_result.get(
        "classification",
        "Unknown"
    )

    static_classification = static_result.get(
        "static_classification",
        "Unknown"
    )

    if ml_classification in [
        "Malware",
        "Benign"
    ]:

        classification = ml_classification

    else:

        classification = static_classification

    # --------------------------------------------------------
    # RISK EXPLANATION
    # --------------------------------------------------------

    risk_explanation = get_risk_explanation(
        static_score,
        ml_result,
        final_score
    )

    # --------------------------------------------------------
    # FILE HASH
    # --------------------------------------------------------

    sha256 = static_result.get(
        "sha256",
        ""
    )

    # --------------------------------------------------------
    # FILE SIZE
    # --------------------------------------------------------

    try:

        file_size = upload_path.stat().st_size

    except Exception:

        file_size = 0

    # --------------------------------------------------------
    # DETECTION RECORD
    # --------------------------------------------------------

    detection = {

        "id": detection_id,

        "timestamp": timestamp,

        "filename": safe_filename,

        "file_size": file_size,

        "sha256": sha256,

        "classification": classification,

        "risk_score": final_score,

        "risk_level": risk_level,

        "risk_explanation": risk_explanation,

        "static_analysis": static_result,

        "ml_analysis": ml_result
    }

    # --------------------------------------------------------
    # LOAD DATABASE
    # --------------------------------------------------------

    db = load_db()

    # --------------------------------------------------------
    # SAVE DETECTION
    # --------------------------------------------------------

    db.setdefault(
        "detections",
        []
    ).append(
        detection
    )

    # --------------------------------------------------------
    # ALERT GENERATION
    # --------------------------------------------------------

    generated_alert = None

    if should_create_alert(
        final_score
    ):

        alert = {

            "id": str(uuid.uuid4()),

            "detection_id": detection_id,

            "timestamp": timestamp,

            "filename": safe_filename,

            "classification": classification,

            "risk_score": final_score,

            "risk_level": risk_level,

            "message": (
                f"High-risk file detected: "
                f"{safe_filename}"
            ),

            "status": "Active"
        }

        db.setdefault(
            "alerts",
            []
        ).append(
            alert
        )

        generated_alert = alert

    # --------------------------------------------------------
    # REPORT GENERATION
    # --------------------------------------------------------

    report = None

    try:

        report = generate_report(
            detection,
            generated_alert
        )

        report["id"] = str(
            uuid.uuid4()
        )

        report["detection_id"] = (
            detection_id
        )

        db.setdefault(
            "reports",
            []
        ).append(
            report
        )

    except Exception as error:

        print(
            "Report generation error:",
            error
        )

    # --------------------------------------------------------
    # SAVE DATABASE
    # --------------------------------------------------------

    save_db(db)

    # --------------------------------------------------------
    # RESPONSE
    # --------------------------------------------------------

    return {

        "success": True,

        "message": "File analyzed successfully",

        "detection": detection,

        "report_id": report.get("id") if report else None,

        "report": report
    }


# ============================================================
# GET ALL DETECTIONS
# ============================================================

@app.get(
    "/api/detections",
    tags=["Detection"],
    summary="List detections",
    description="Return detection history and classification results."
)
def get_detections():

    db = load_db()

    detections = db.get(
        "detections",
        []
    )

    return {
        "success": True,
        "count": len(detections),
        "detections": detections
    }


# ============================================================
# GET SINGLE DETECTION
# ============================================================

@app.get(
    "/api/analyze/{detection_id}",
    tags=["File Analysis"],
    summary="Get a detection analysis",
    description="Return the stored analysis for a detection ID."
)
def get_detection(
    detection_id: str
):

    db = load_db()

    detections = db.get(
        "detections",
        []
    )

    for detection in detections:

        if detection.get("id") == detection_id:

            return {
                "success": True,
                "detection": detection
            }

    raise HTTPException(
        status_code=404,
        detail="Detection not found"
    )


# ============================================================
# GET ALERTS
# ============================================================

@app.get(
    "/api/alerts",
    tags=["Threat Monitoring"],
    summary="List threat alerts",
    description="Return alerts generated from analyzed files."
)
def get_alerts():

    db = load_db()

    alerts = db.get(
        "alerts",
        []
    )

    return {
        "success": True,
        "count": len(alerts),
        "alerts": alerts
    }


# ============================================================
# GET REPORTS
# ============================================================

@app.get(
    "/api/reports",
    tags=["Reports"],
    summary="List analysis reports",
    description="Return generated malware analysis reports."
)
def get_reports():

    db = load_db()

    reports = db.get(
        "reports",
        []
    )

    return {
        "success": True,
        "count": len(reports),
        "reports": reports
    }


def find_report(report_id):

    return next(
        (
            report for report in load_db().get("reports", [])
            if report.get("id") == report_id
        ),
        None
    )


@app.get(
    "/api/reports/{report_id}",
    tags=["Reports"],
    summary="Get an analysis report",
    description="Return the complete stored report for a report ID."
)
def get_report(report_id: str):

    report = find_report(report_id)

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    return {
        "success": True,
        "report": report
    }


@app.get(
    "/api/reports/{report_id}/pdf",
    tags=["Reports"],
    summary="Download a PDF report",
    description="Generate a formatted PDF from the stored analysis report."
)
def download_report_pdf(report_id: str):

    report = find_report(report_id)

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        output = build_pdf_report(report)
    except Exception as error:
        print("PDF report generation error:", error)
        raise HTTPException(
            status_code=500,
            detail="Unable to generate PDF report"
        )

    return StreamingResponse(
        output,
        media_type="application/pdf",
        headers={
            "Content-Disposition": (
                f'attachment; filename="ThreatLens_Report_{report_id}.pdf"'
            )
        }
    )


@app.get(
    "/api/reports/{report_id}/excel",
    tags=["Reports"],
    summary="Download an Excel report",
    description="Generate a formatted Excel workbook from the stored analysis report."
)
def download_report_excel(report_id: str):

    report = find_report(report_id)

    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    try:
        output = build_excel_report(report)
    except Exception as error:
        print("Excel report generation error:", error)
        raise HTTPException(
            status_code=500,
            detail="Unable to generate Excel report"
        )

    return StreamingResponse(
        output,
        media_type=(
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        ),
        headers={
            "Content-Disposition": (
                f'attachment; filename="ThreatLens_Report_{report_id}.xlsx"'
            )
        }
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.get(
    "/api/dashboard",
    tags=["Threat Monitoring"],
    summary="Get dashboard metrics",
    description="Return threat, risk, detection, and alert summary metrics."
)
def get_dashboard():

    db = load_db()

    detections = db.get(
        "detections",
        []
    )

    alerts = db.get(
        "alerts",
        []
    )

    total_files = len(
        detections
    )

    malware_count = sum(
        1
        for d in detections
        if d.get("classification") == "Malware"
    )

    benign_count = sum(
        1
        for d in detections
        if d.get("classification") == "Benign"
    )

    suspicious_count = sum(
        1
        for d in detections
        if d.get("classification") == "Suspicious"
    )

    high_risk = sum(
        1
        for d in detections
        if d.get("risk_level") == "High"
    )

    medium_risk = sum(
        1
        for d in detections
        if d.get("risk_level") == "Medium"
    )

    low_risk = sum(
        1
        for d in detections
        if d.get("risk_level") == "Low"
    )

    return {

        "success": True,

        "dashboard": {

            "total_files":
                total_files,

            "malware":
                malware_count,

            "benign":
                benign_count,

            "suspicious":
                suspicious_count,

            "high_risk":
                high_risk,

            "medium_risk":
                medium_risk,

            "low_risk":
                low_risk,

            "total_alerts":
                len(alerts)
        }
    }


@app.post(
    "/api/auth/forgot-password",
    tags=["Authentication"],
    summary="Request a password reset",
    description="Send a password reset link when SMTP delivery is configured."
)
def forgot_password(request: ForgotPasswordRequest):

    email = request.email.strip().lower()
    db = load_db()
    user = next(
        (stored_user for stored_user in db.get("users", [])
         if stored_user.get("email") == email),
        None
    )

    if not user:
        return {
            "message": "If an account exists for that email, a reset link has been sent."
        }

    token = secrets.token_urlsafe(32)
    user["password_reset_token_hash"] = hashlib.sha256(
        token.encode("utf-8")
    ).hexdigest()
    user["password_reset_expires_at"] = datetime.now().timestamp() + (30 * 60)
    save_db(db)

    try:
        send_password_reset_email(email, token)
    except (OSError, ValueError, RuntimeError, smtplib.SMTPException):
        user.pop("password_reset_token_hash", None)
        user.pop("password_reset_expires_at", None)
        save_db(db)
        raise HTTPException(
            status_code=503,
            detail="Password reset email delivery is not configured"
        )

    return {
        "message": "If an account exists for that email, a reset link has been sent."
    }


@app.post(
    "/api/auth/reset-password",
    tags=["Authentication"],
    summary="Reset a password",
    description="Set a new password using a valid one-time reset token."
)
def reset_password(request: ResetPasswordRequest):

    if (
        len(request.password) < 8
        or not any(character.isalpha() for character in request.password)
        or not any(character.isdigit() for character in request.password)
        or not any(not character.isalnum() for character in request.password)
    ):
        raise HTTPException(
            status_code=400,
            detail="Password must be at least 8 characters and include letters, numbers, and symbols"
        )

    token_hash = hashlib.sha256(request.token.encode("utf-8")).hexdigest()
    db = load_db()
    user = next(
        (
            stored_user for stored_user in db.get("users", [])
            if hmac.compare_digest(
                stored_user.get("password_reset_token_hash", ""),
                token_hash
            )
        ),
        None
    )

    if (
        not user
        or user.get("password_reset_expires_at", 0) < datetime.now().timestamp()
    ):
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user["password_hash"] = hash_password(request.password)
    user.pop("password_reset_token_hash", None)
    user.pop("password_reset_expires_at", None)
    save_db(db)

    return {"message": "Password reset successfully"}