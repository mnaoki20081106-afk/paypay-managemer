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
import sms_service
import sms_storage
from sms_provider import sms_items, public_phone
from sms_api_base import APIError as SMSAPIError

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


class BuyNumberRequest(BaseModel):
    service_key: str
    country_id: int = 182

    @field_validator("service_key")
    @classmethod
    def valid_service(cls, v: str) -> str:
        import re
        if not re.fullmatch(r'[a-zA-Z0-9_-]{2,40}', v):
            raise ValueError("invalid service_key")
        return v

    @field_validator("country_id")
    @classmethod
    def valid_country(cls, v: int) -> int:
        if not 1 <= v <= 99999:
            raise ValueError("country_id out of range")
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


# ── SMS routes ────────────────────────────────────────────────────────────────

@app.get("/api/sms/status")
async def api_sms_status():
    if not sms_service.is_configured():
        return {"configured": False, "balance": None}
    try:
        provider = sms_service.get_provider()
        profile = await provider.api.profile()
        balance = str(provider.wallet_balance(profile))
        return {"configured": True, "balance": balance}
    except SMSAPIError as e:
        return {"configured": True, "balance": None, "error": str(e)}


@app.get("/api/sms/services")
async def api_sms_services():
    if not sms_service.is_configured():
        raise HTTPException(503, detail={"error": "sms_not_configured"})
    try:
        provider = sms_service.get_provider()
        services = await provider.available_services(182)
        return services
    except SMSAPIError as e:
        raise HTTPException(400, detail={"error": str(e)})


@app.get("/api/sms/numbers")
async def api_sms_numbers():
    if not sms_service.is_configured():
        raise HTTPException(503, detail={"error": "sms_not_configured"})
    try:
        provider = sms_service.get_provider()
        orders = await provider.active()
        result = []
        for order in orders:
            order_id = str(order.get("id", ""))
            local = sms_storage.get_number(order_id)
            texts = sms_items(order)
            service_raw = order.get("service", {})
            service_key = service_raw.get("key", "") if isinstance(service_raw, dict) else ""
            result.append({
                "order_id": order_id,
                "phone": public_phone(order.get("phone_number", "")),
                "service_key": service_key or (local["service_key"] if local else ""),
                "is_active": order.get("is_active", False),
                "expires_at": order.get("expiration_date"),
                "sms_count": len(texts),
                "sms": texts,
            })
        return result
    except SMSAPIError as e:
        raise HTTPException(400, detail={"error": str(e)})


@app.post("/api/sms/numbers")
async def api_sms_buy(req: BuyNumberRequest):
    if not sms_service.is_configured():
        raise HTTPException(503, detail={"error": "sms_not_configured"})
    try:
        provider = sms_service.get_provider()
        order_id, phone, expires_at = await provider.buy(req.service_key, req.country_id)
        sms_storage.save_number(order_id, req.service_key, req.country_id,
                                phone, expires_at)
        return {
            "order_id": order_id,
            "phone": public_phone(phone),
            "service_key": req.service_key,
            "expires_at": expires_at,
        }
    except sms_service.OutOfStockError as e:
        raise HTTPException(402, detail={"error": str(e)})
    except SMSAPIError as e:
        raise HTTPException(400, detail={"error": str(e)})


@app.get("/api/sms/numbers/{order_id}/sms")
async def api_sms_poll(order_id: str):
    if not sms_service.is_configured():
        raise HTTPException(503, detail={"error": "sms_not_configured"})
    try:
        provider = sms_service.get_provider()
        orders = await provider.active()
        for order in orders:
            if str(order.get("id", "")) == order_id:
                texts = sms_items(order)
                return {"order_id": order_id, "sms": texts, "count": len(texts)}
        raise HTTPException(404, detail={"error": "order_not_found"})
    except SMSAPIError as e:
        raise HTTPException(400, detail={"error": str(e)})


@app.delete("/api/sms/numbers/{order_id}")
async def api_sms_cancel(order_id: str):
    if not sms_service.is_configured():
        raise HTTPException(503, detail={"error": "sms_not_configured"})
    local = sms_storage.get_number(order_id)
    if not local:
        # try to get service_key from active orders
        try:
            provider = sms_service.get_provider()
            orders = await provider.active()
            match = next((o for o in orders if str(o.get("id", "")) == order_id), None)
            if not match:
                raise HTTPException(404, detail={"error": "order_not_found"})
            service_raw = match.get("service", {})
            service_key = service_raw.get("key", "") if isinstance(service_raw, dict) else ""
            if not service_key:
                raise HTTPException(400, detail={"error": "service_key_unknown"})
        except SMSAPIError as e:
            raise HTTPException(400, detail={"error": str(e)})
    else:
        service_key = local["service_key"]
    try:
        provider = sms_service.get_provider()
        await provider.cancel(order_id, service_key)
        sms_storage.delete_number(order_id)
        return {"cancelled": order_id}
    except SMSAPIError as e:
        raise HTTPException(400, detail={"error": str(e)})


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
