"""
Database Schemas for EV Spotter

Each Pydantic model represents a MongoDB collection. The collection name is the
lowercase of the class name. Example: class User -> "user" collection.
"""
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
from datetime import datetime

class User(BaseModel):
    phone: str = Field(..., description="Mobile number in E.164 or local format")
    carNumber: Optional[str] = Field(None, description="Indian vehicle registration number")
    verified: bool = Field(False)
    roles: List[str] = Field(default_factory=lambda: ["user"])  # ["user", "admin"]

    @field_validator("carNumber")
    @classmethod
    def validate_car_number(cls, v):
        if v is None:
            return v
        import re
        pattern = r"^[A-Z]{2}\d{2}[A-Z]{2}\d{4}$"
        if not re.match(pattern, v):
            raise ValueError("Invalid car number format. Expected like MH12AB1234")
        return v

class Station(BaseModel):
    name: str
    operator: Optional[str] = None
    location: dict = Field(..., description="{ lat: Number, lon: Number }")
    connectorTypes: List[str] = Field(default_factory=list)
    powerKW: Optional[float] = None
    tomtomStationId: Optional[str] = Field(None, description="TomTom station ID for live availability")
    amenities: List[str] = Field(default_factory=list)
    city: Optional[str] = None

class Booking(BaseModel):
    userId: str = Field(..., description="User ObjectId as string")
    stationId: str = Field(..., description="Station ObjectId as string")
    date: datetime
    timeSlot: str
    status: str = Field("active", description="active | cancelled | completed | rescheduled")

class OtpEntry(BaseModel):
    phone: str
    otp_hash: str
    expires_at: datetime
    attempts: int = 0
    created_at: datetime
    ip: Optional[str] = None
