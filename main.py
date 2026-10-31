"""PayPay Manager — FastAPI web application."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, field_validator

import paypay_auth
import paypay_balance
import paypay_payment
import storage

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)

app = FastAPI(title="PayPay Manager", docs_url=None, redoc_url=None)

STATIC = Path(__file__).parent / "static"


# ── Models ────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    phone: str
    password: str

    @field_validator("phone")
    @classmethod
    def clean_phone(cls, v: str) -> str:
        v = v.strip().replace("-", "").replace(" ", "")
        if not v:
            raise ValueError("phone required")
        return v

    @field_validator("password")
    @classmethod
    def non_empty_password(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("password required")
        return v


class OtpRequest(BaseModel):
    phone: str
    otp: str

    @field_validator("otp")
    @classmethod
    def digits_only(cls, v: str) -> str:
        v = v.strip()
        if not v.isdigit() or len(v) != 4:
            raise ValueError("OTP must be 4 digits")
        return v


class ReceiveRequest(BaseModel):
    phone: str
    link: str
    amount: int

    @field_validator("amount")
    @classmethod
    def positive(cls, v: int) -> int:
        if v < 1:
            raise ValueError("amount must be >= 1")
        return v


# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/api/health")
async def api_health():
    return {"ok": True}


@app.get("/api/accounts")
async def api_list_accounts():
    return paypay_auth.list_accounts()


@app.get("/api/accounts/{phone}/status")
async def api_account_status(phone: str):
    phones = storage.list_phones()
    if phone not in phones:
        raise HTTPException(404, "Account not found")
    return paypay_auth.account_status(phone)


@app.post("/api/accounts/login")
async def api_login(req: LoginRequest):
    try:
        result = await paypay_auth.start_login(req.phone, req.password)
        return result
    except paypay_auth.PayPayAuthError as e:
        raise HTTPException(400, detail={"error": e.reason,
                                         "status": e.status,
                                         "code": e.provider_code})


@app.post("/api/accounts/otp")
async def api_otp(req: OtpRequest):
    try:
        result = await paypay_auth.submit_otp(req.phone, req.otp)
        return result
    except paypay_auth.PayPayAuthError as e:
        raise HTTPException(400, detail={"error": e.reason,
                                         "status": e.status,
                                         "code": e.provider_code})


@app.post("/api/accounts/{phone}/refresh")
async def api_refresh(phone: str):
    phones = storage.list_phones()
    if phone not in phones:
        raise HTTPException(404, "Account not found")
    try:
        result = await paypay_auth.refresh_account(phone)
        return result
    except paypay_auth.PayPayAuthError as e:
        raise HTTPException(400, detail={"error": e.reason})


@app.get("/api/accounts/{phone}/balance")
async def api_balance(phone: str):
    phones = storage.list_phones()
    if phone not in phones:
        raise HTTPException(404, "Account not found")
    try:
        result = await paypay_balance.get_balance(phone)
        return {"phone": phone, "balance": result["balance"]}
    except paypay_balance.BalanceError as e:
        raise HTTPException(400, detail={"error": e.reason})
    except paypay_auth.PayPayAuthError as e:
        raise HTTPException(401, detail={"error": e.reason})


@app.delete("/api/accounts/{phone}")
async def api_delete(phone: str):
    deleted = storage.delete_account(phone)
    if not deleted:
        raise HTTPException(404, "Account not found")
    return {"deleted": phone}


@app.get("/api/payments")
async def api_payments():
    try:
        return paypay_payment.list_payments()
    except Exception:
        return []


@app.post("/api/payments/receive")
async def api_receive(req: ReceiveRequest):
    try:
        result = await paypay_payment.receive_link(req.phone, req.link, req.amount)
        return result
    except paypay_payment.TemporaryHold as e:
        raise HTTPException(
            202,
            detail={"error": "temporary_hold", "message": e.message,
                    "payment_id": e.payment_id, "provider_code": e.provider_code},
        )
    except paypay_payment.PaymentError as e:
        raise HTTPException(400, detail={"error": e.kind, "message": e.message})
    except paypay_auth.PayPayAuthError as e:
        raise HTTPException(401, detail={"error": e.reason})


# ── Static files ──────────────────────────────────────────────────────────────

@app.get("/")
async def root():
    return FileResponse(STATIC / "index.html")


@app.exception_handler(404)
async def not_found(request: Request, exc):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "not_found"}, status_code=404)
    return FileResponse(STATIC / "index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
