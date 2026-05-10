from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


class SenderInfo(BaseModel):
    from_raw: str
    from_domain: str
    display_name: str


class AuthResults(BaseModel):
    spf: str   # "pass" | "fail" | "none"
    dkim: str
    dmarc: str
    reply_to: Optional[str] = None
    return_path: Optional[str] = None


class UrlEntry(BaseModel):
    display_text: str
    href: str


class AttachmentMeta(BaseModel):
    filename: str
    mime_type: str
    size_bytes: int


class BodySignals(BaseModel):
    char_count: int
    urgency_phrases: list[str] = Field(default_factory=list)
    credential_phrases: list[str] = Field(default_factory=list)
    financial_phrases: list[str] = Field(default_factory=list)
    otp_phrases: list[str] = Field(default_factory=list)
    has_invisible_text: bool = False
    generic_greeting: bool = False
    fake_security_alert: bool = False
    tracking_pixel_domains: list[str] = Field(default_factory=list)
    spelling_error_count: int = 0


class EmailMetadata(BaseModel):
    timestamp: datetime
    received_count: int
    sender_ip: Optional[str] = None


class EmailPayload(BaseModel):
    message_id: str
    sender: SenderInfo
    auth: AuthResults
    subject: str
    urls: list[UrlEntry] = Field(default_factory=list)
    attachments: list[AttachmentMeta] = Field(default_factory=list)
    body_signals: BodySignals
    metadata: EmailMetadata
