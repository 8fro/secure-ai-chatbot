# otp_app.py
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime, timedelta
import secrets, hashlib, os
from dotenv import load_dotenv
import smtplib
from email.message import EmailMessage


try:
    from twilio.rest import Client
    TWILIO_AVAILABLE = True
except Exception:
    TWILIO_AVAILABLE = False

load_dotenv()

EMAIL_HOST = os.getenv("EMAIL_HOST", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", "465"))
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")

TWILIO_SID = os.getenv("TWILIO_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
TWILIO_FROM = os.getenv("TWILIO_FROM")

OTP_SALT = os.getenv("OTP_SALT", "change_this_salt")
OTP_EXPIRY = int(os.getenv("OTP_EXPIRY_SECONDS", "300"))

app = FastAPI(title="OTP Auth Service (dev)")

# In-memory store: contact -> { "hash":..., "expires_at":..., "tries": int }
otp_store = {}

class RequestOTP(BaseModel):
    contact: str  # email or phone (+countrycode)
    method: str = "email"  # "email" or "sms"
    length: int = 6

class VerifyOTP(BaseModel):
    contact: str
    otp: str

def generate_otp(length=6):
    digits = "0123456789"
    return "".join(secrets.choice(digits) for _ in range(length))

def hash_otp(otp: str):
    return hashlib.sha256((otp + OTP_SALT).encode()).hexdigest()

def send_email_otp(to_email: str, otp: str):
    if not EMAIL_USER or not EMAIL_PASS:
        raise Exception("Email credentials not configured")
    msg = EmailMessage()
    msg["Subject"] = "Your OTP code"
    msg["From"] = EMAIL_USER
    msg["To"] = to_email
    msg.set_content(f"Your OTP is: {otp}\nIt will expire in {OTP_EXPIRY//60} minutes.")
    with smtplib.SMTP_SSL(EMAIL_HOST, EMAIL_PORT) as smtp:
        smtp.login(EMAIL_USER, EMAIL_PASS)
        smtp.send_message(msg)

def send_sms_otp(to_phone: str, otp: str):
    if not (TWILIO_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM):
        raise Exception("Twilio not configured")
    client = Client(TWILIO_SID, TWILIO_AUTH_TOKEN)
    msg = client.messages.create(body=f"Your OTP: {otp}", from_=TWILIO_FROM, to=to_phone)
    return msg.sid

@app.post("/request-otp")
def request_otp(payload: RequestOTP):
    contact = payload.contact.strip()
    method = payload.method.lower()
    if method not in ("email", "sms"):
        raise HTTPException(status_code=400, detail="method must be 'email' or 'sms'")

    otp = generate_otp(payload.length)
    hashed = hash_otp(otp)
    expires_at = datetime.utcnow() + timedelta(seconds=OTP_EXPIRY)
    otp_store[contact] = {"hash": hashed, "expires_at": expires_at, "tries": 0}

    try:
        if method == "email":
            send_email_otp(contact, otp)
        else:
            send_sms_otp(contact, otp)
    except Exception as e:
        otp_store.pop(contact, None)
        raise HTTPException(status_code=500, detail=f"Failed to send OTP: {e}")

    return {"status": "ok", "message": "OTP sent (if contact valid)"}

@app.post("/verify-otp")
def verify_otp(payload: VerifyOTP):
    contact = payload.contact.strip()
    rec = otp_store.get(contact)
    if not rec:
        raise HTTPException(status_code=400, detail="No OTP requested for this contact")

    if datetime.utcnow() > rec["expires_at"]:
        otp_store.pop(contact, None)
        raise HTTPException(status_code=400, detail="OTP expired")

    if rec["tries"] >= 5:
        otp_store.pop(contact, None)
        raise HTTPException(status_code=400, detail="Too many attempts")

    if hash_otp(payload.otp) == rec["hash"]:
        otp_store.pop(contact, None)
        # Here: you would create a session/token and return it
        return {"status": "ok", "message": "Verified"}
    else:
        rec["tries"] += 1
        raise HTTPException(status_code=400, detail="Invalid OTP")
# secure-ai-chatbot
Secure AI Chatbot with OTP Authentication (Python + FastAPI)
