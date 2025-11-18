import os
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Any

import requests
from fastapi import FastAPI, HTTPException, Depends, Body, Header, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from bson import ObjectId

from database import db, create_document, get_documents

# Configuration
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
TOMTOM_API_KEY = os.getenv("TOMTOM_API_KEY")
OTP_TTL_MINUTES = 5

logger = logging.getLogger("evspotter")
logging.basicConfig(level=logging.INFO)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
auth_scheme = HTTPBearer()

# FastAPI app
app = FastAPI(title="EV Spotter API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utility helpers
class PyObjectId(ObjectId):
    @classmethod
    def __get_validators__(cls):
        yield cls.validate

    @classmethod
    def validate(cls, v):
        if isinstance(v, ObjectId):
            return v
        if not ObjectId.is_valid(v):
            raise ValueError("Invalid ObjectId")
        return ObjectId(v)


def hash_text(text: str) -> str:
    return pwd_context.hash(text)


def verify_hash(text: str, hashed: str) -> bool:
    return pwd_context.verify(text, hashed)


def create_jwt(payload: dict, expires_minutes: int = 60 * 24 * 7) -> str:
    to_encode = payload.copy()
    exp = datetime.now(timezone.utc) + timedelta(minutes=expires_minutes)
    to_encode.update({"exp": exp})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user(token: HTTPAuthorizationCredentials = Depends(auth_scheme)) -> dict:
    try:
        data = jwt.decode(token.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        return data
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")


def require_role(role: str):
    def checker(user: dict = Depends(get_current_user)):
        roles = user.get("roles", [])
        if role not in roles:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker


# Pydantic models
class SendOtpRequest(BaseModel):
    phone: str

class VerifyOtpRequest(BaseModel):
    phone: str
    otp: str
    carNumber: Optional[str] = None

class AuthResponse(BaseModel):
    token: str
    user: dict

class StationIn(BaseModel):
    name: str
    operator: Optional[str] = None
    location: dict
    connectorTypes: List[str] = Field(default_factory=list)
    powerKW: Optional[float] = None
    tomtomStationId: Optional[str] = None
    amenities: List[str] = Field(default_factory=list)
    city: Optional[str] = None

class StationOut(StationIn):
    id: str

class BookingIn(BaseModel):
    stationId: str
    date: datetime
    timeSlot: str

class BookingUpdate(BaseModel):
    status: Optional[str] = None
    timeSlot: Optional[str] = None

class RouteRequest(BaseModel):
    origin: dict
    destination: dict


# Index routes
@app.get("/")
def root():
    return {"name": "EV Spotter API", "status": "ok"}

@app.get("/test")
def test_database():
    info = {
        "backend": "ok",
        "database": "connected" if db is not None else "not-configured",
        "collections": db.list_collection_names() if db is not None else [],
        "tomtom": "configured" if TOMTOM_API_KEY else "missing"
    }
    return info


# Auth + OTP
@app.post("/api/auth/send-otp")
def send_otp(req: SendOtpRequest, request: Request):
    if not re.fullmatch(r"^[0-9]{10,13}$", req.phone):
        raise HTTPException(status_code=400, detail="Invalid phone number")

    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    otp = f"{int.from_bytes(os.urandom(2), 'big') % 1000000:06d}"
    otp_hash = hash_text(otp)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=OTP_TTL_MINUTES)

    payload = {
        "phone": req.phone,
        "otp_hash": otp_hash,
        "expires_at": expires_at,
        "attempts": 0,
        "created_at": datetime.now(timezone.utc),
        "ip": request.client.host if request.client else None,
    }
    db["otpentry"].delete_many({"phone": req.phone})
    db["otpentry"].insert_one(payload)

    # NOTE: For demo, log the OTP to server logs. Do not expose to client.
    logger.info(f"OTP for {req.phone}: {otp}")

    return {"message": "OTP sent successfully"}


@app.post("/api/auth/verify-otp", response_model=AuthResponse)
def verify_otp(req: VerifyOtpRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")

    entry = db["otpentry"].find_one({"phone": req.phone})
    if not entry:
        raise HTTPException(status_code=400, detail="OTP not requested")

    if entry.get("expires_at") < datetime.now(timezone.utc):
        db["otpentry"].delete_one({"_id": entry["_id"]})
        raise HTTPException(status_code=400, detail="OTP expired")

    if not verify_hash(req.otp, entry.get("otp_hash")):
        db["otpentry"].update_one({"_id": entry["_id"]}, {"$inc": {"attempts": 1}})
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Upsert user
    user = db["user"].find_one({"phone": req.phone})
    car_number = req.carNumber
    if car_number:
        if not re.match(r"^[A-Z]{2}\d{2}[A-Z]{2}\d{4}$", car_number):
            raise HTTPException(status_code=400, detail="Invalid car number format")
    if user:
        db["user"].update_one({"_id": user["_id"]}, {"$set": {"verified": True, "carNumber": car_number or user.get("carNumber")}})
        user = db["user"].find_one({"_id": user["_id"]})
    else:
        roles = ["user"]
        user_id = db["user"].insert_one({
            "phone": req.phone,
            "carNumber": car_number,
            "verified": True,
            "roles": roles,
            "created_at": datetime.now(timezone.utc)
        }).inserted_id
        user = db["user"].find_one({"_id": user_id})

    db["otpentry"].delete_one({"_id": entry["_id"]})

    user_payload = {
        "id": str(user["_id"]),
        "phone": user.get("phone"),
        "carNumber": user.get("carNumber"),
        "roles": user.get("roles", ["user"]),
        "verified": True
    }
    token = create_jwt(user_payload)
    return {"token": token, "user": user_payload}


# Stations
@app.get("/api/stations", response_model=List[StationOut])
def list_stations(city: Optional[str] = None):
    stations = db["station"].find({"city": city} if city else {})
    return [
        StationOut(
            id=str(s["_id"]),
            name=s.get("name"),
            operator=s.get("operator"),
            location=s.get("location"),
            connectorTypes=s.get("connectorTypes", []),
            powerKW=s.get("powerKW"),
            tomtomStationId=s.get("tomtomStationId"),
            amenities=s.get("amenities", []),
            city=s.get("city")
        ) for s in stations
    ]

@app.get("/api/stations/{station_id}", response_model=StationOut)
def get_station(station_id: str):
    s = db["station"].find_one({"_id": PyObjectId.validate(station_id)})
    if not s:
        raise HTTPException(status_code=404, detail="Station not found")
    return StationOut(
        id=str(s["_id"]),
        name=s.get("name"),
        operator=s.get("operator"),
        location=s.get("location"),
        connectorTypes=s.get("connectorTypes", []),
        powerKW=s.get("powerKW"),
        tomtomStationId=s.get("tomtomStationId"),
        amenities=s.get("amenities", []),
        city=s.get("city")
    )

@app.get("/api/stations/{station_id}/live")
def station_live_availability(station_id: str):
    s = db["station"].find_one({"_id": PyObjectId.validate(station_id)})
    if not s:
        raise HTTPException(status_code=404, detail="Station not found")
    ttid = s.get("tomtomStationId")
    if not ttid:
        raise HTTPException(status_code=400, detail="No TomTom station id for this station")
    if not TOMTOM_API_KEY:
        raise HTTPException(status_code=500, detail="TomTom API key not configured")
    url = f"https://api.tomtom.com/ev-charging-stations-availability/2/stations/{ttid}/availability?key={TOMTOM_API_KEY}"
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()

@app.get("/api/tt/availability/{tt_station_id}")
def availability_by_tomtom_id(tt_station_id: str):
    if not TOMTOM_API_KEY:
        raise HTTPException(status_code=500, detail="TomTom API key not configured")
    url = f"https://api.tomtom.com/ev-charging-stations-availability/2/stations/{tt_station_id}/availability?key={TOMTOM_API_KEY}"
    r = requests.get(url, timeout=15)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()

@app.post("/api/stations", dependencies=[Depends(require_role("admin"))], response_model=StationOut)
def create_station(station: StationIn):
    res = db["station"].insert_one(station.model_dump())
    s = db["station"].find_one({"_id": res.inserted_id})
    return StationOut(id=str(s["_id"]), **{k: s.get(k) for k in station.model_dump().keys()})

@app.patch("/api/stations/{station_id}", dependencies=[Depends(require_role("admin"))])
def update_station(station_id: str, patch: dict = Body(...)):
    db["station"].update_one({"_id": PyObjectId.validate(station_id)}, {"$set": patch})
    s = db["station"].find_one({"_id": PyObjectId.validate(station_id)})
    if not s:
        raise HTTPException(status_code=404, detail="Station not found")
    s["id"] = str(s.pop("_id"))
    return s

@app.delete("/api/stations/{station_id}", dependencies=[Depends(require_role("admin"))])
def delete_station(station_id: str):
    db["station"].delete_one({"_id": PyObjectId.validate(station_id)})
    return {"deleted": True}


# Bookings
@app.post("/api/bookings")
def create_booking(b: BookingIn, user=Depends(get_current_user)):
    # ensure station exists
    s = db["station"].find_one({"_id": PyObjectId.validate(b.stationId)})
    if not s:
        raise HTTPException(status_code=404, detail="Station not found")
    doc = {
        "userId": PyObjectId.validate(user["id"]),
        "stationId": PyObjectId.validate(b.stationId),
        "date": b.date,
        "timeSlot": b.timeSlot,
        "status": "active",
        "created_at": datetime.now(timezone.utc)
    }
    res = db["booking"].insert_one(doc)
    bk = db["booking"].find_one({"_id": res.inserted_id})
    bk["id"] = str(bk.pop("_id"))
    bk["userId"] = str(bk["userId"]) 
    bk["stationId"] = str(bk["stationId"]) 
    return bk

@app.get("/api/bookings/{user_id}")
def get_user_bookings(user_id: str, user=Depends(get_current_user)):
    if user_id != user.get("id") and "admin" not in user.get("roles", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    items = list(db["booking"].find({"userId": PyObjectId.validate(user_id)}).sort("created_at", -1))
    for it in items:
        it["id"] = str(it.pop("_id"))
        it["userId"] = str(it["userId"]) 
        it["stationId"] = str(it["stationId"]) 
    return items

@app.patch("/api/bookings/{booking_id}")
def update_booking(booking_id: str, patch: BookingUpdate, user=Depends(get_current_user)):
    bk = db["booking"].find_one({"_id": PyObjectId.validate(booking_id)})
    if not bk:
        raise HTTPException(status_code=404, detail="Booking not found")
    if str(bk["userId"]) != user.get("id") and "admin" not in user.get("roles", []):
        raise HTTPException(status_code=403, detail="Forbidden")
    updates = {k: v for k, v in patch.model_dump().items() if v is not None}
    if not updates:
        return {"updated": False}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["booking"].update_one({"_id": bk["_id"]}, {"$set": updates})
    bk = db["booking"].find_one({"_id": bk["_id"]})
    bk["id"] = str(bk.pop("_id"))
    bk["userId"] = str(bk["userId"]) 
    bk["stationId"] = str(bk["stationId"]) 
    return bk


# TomTom integration helpers (proxy so key is never exposed)
@app.get("/api/nearby")
def nearby_ev(lat: float, lon: float, radius: int = 5000):
    if not TOMTOM_API_KEY:
        raise HTTPException(status_code=500, detail="TomTom API key not configured")
    url = f"https://api.tomtom.com/ev-search/3/search/nearby?lat={lat}&lon={lon}&radius={radius}&key={TOMTOM_API_KEY}"
    r = requests.get(url, timeout=20)
    if r.status_code != 200:
        raise HTTPException(status_code=r.status_code, detail=r.text)
    return r.json()

@app.post("/api/route")
def route(req: RouteRequest):
    if not TOMTOM_API_KEY:
        raise HTTPException(status_code=500, detail="TomTom API key not configured")
    start = f"{req.origin.get('lat')},{req.origin.get('lon')}"
    end = f"{req.destination.get('lat')},{req.destination.get('lon')}"
    route_url = f"https://api.tomtom.com/routing/1/calculateRoute/{start}:{end}/json?key={TOMTOM_API_KEY}&traffic=true"
    rr = requests.get(route_url, timeout=30)
    if rr.status_code != 200:
        raise HTTPException(status_code=rr.status_code, detail=rr.text)
    route_data = rr.json()

    # Heuristic: fetch chargers near destination as a simple suggestion
    dest_lat = req.destination.get('lat')
    dest_lon = req.destination.get('lon')
    ev_url = f"https://api.tomtom.com/ev-search/3/search/nearby?lat={dest_lat}&lon={dest_lon}&radius=10000&key={TOMTOM_API_KEY}"
    er = requests.get(ev_url, timeout=20)
    ev_data = er.json() if er.status_code == 200 else {"results": []}

    return {"route": route_data, "suggested": ev_data}


# Simple admin bootstrap endpoint (optional): promote a user to admin by phone (protect with env gate)
@app.post("/api/admin/promote")
def promote_admin(phone: str = Body(..., embed=True), admin_key: Optional[str] = Header(None)):
    expected = os.getenv("ADMIN_BOOTSTRAP_KEY")
    if not expected or admin_key != expected:
        raise HTTPException(status_code=403, detail="Forbidden")
    u = db["user"].find_one({"phone": phone})
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    roles = list(set(u.get("roles", []) + ["admin"]))
    db["user"].update_one({"_id": u["_id"]}, {"$set": {"roles": roles}})
    return {"promoted": True, "roles": roles}


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
