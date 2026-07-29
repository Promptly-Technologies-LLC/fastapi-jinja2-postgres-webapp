"""Validation for public website lead forms."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, EmailStr, Field, ValidationError, field_validator

PHONE_PATTERN = re.compile(r"^[\d\s()+\-.]{7,20}$")
NAME_PATTERN = re.compile(r"^[\w\s.'-]{1,80}$", re.UNICODE)
ORG_PATTERN = re.compile(r"^[\w\s.'&,\-/()]{1,120}$", re.UNICODE)


def _clean_optional(value: str | None) -> str | None:
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _validation_errors(exc: ValidationError) -> dict[str, str]:
    errors: dict[str, str] = {}
    for error in exc.errors():
        loc = error.get("loc", ())
        if not loc:
            continue
        field = str(loc[0])
        message = error.get("msg", "Invalid value")
        if message.startswith("Value error, "):
            message = message.removeprefix("Value error, ")
        errors.setdefault(field, message)
    return errors


class BookDemoSubmission(BaseModel):
    work_email: EmailStr
    first_name: str = Field(min_length=1, max_length=80)
    last_name: str = Field(min_length=1, max_length=80)
    company: str = Field(min_length=1, max_length=120)
    trade: str = Field(min_length=1, max_length=80)
    phone: str = Field(min_length=7, max_length=20)
    technicians: str | None = None
    phone_answerer: str | None = None

    @field_validator("first_name", "last_name")
    @classmethod
    def validate_name_fields(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field is required.")
        if not NAME_PATTERN.match(cleaned):
            raise ValueError("Contains invalid characters.")
        return cleaned

    @field_validator("company", "trade")
    @classmethod
    def validate_org_fields(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field is required.")
        if not ORG_PATTERN.match(cleaned):
            raise ValueError("Contains invalid characters.")
        return cleaned

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        cleaned = value.strip()
        if not PHONE_PATTERN.match(cleaned):
            raise ValueError("Enter a valid phone number.")
        return cleaned

    @field_validator("technicians", "phone_answerer", mode="before")
    @classmethod
    def normalize_optional(cls, value: str | None) -> str | None:
        return _clean_optional(value)

    @classmethod
    def from_form(cls, **raw: Any) -> tuple[BookDemoSubmission | None, dict[str, str]]:
        try:
            return cls.model_validate(raw), {}
        except ValidationError as exc:
            return None, _validation_errors(exc)


class CallMeSubmission(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    business: str = Field(min_length=1, max_length=120)
    email: EmailStr
    phone: str = Field(min_length=7, max_length=20)
    industry: str = Field(min_length=1, max_length=80)
    crm: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field is required.")
        if not NAME_PATTERN.match(cleaned):
            raise ValueError("Contains invalid characters.")
        return cleaned

    @field_validator("business", "industry")
    @classmethod
    def validate_org_fields(cls, value: str) -> str:
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("This field is required.")
        if not ORG_PATTERN.match(cleaned):
            raise ValueError("Contains invalid characters.")
        return cleaned

    @field_validator("phone", mode="before")
    @classmethod
    def normalize_phone(cls, value: str) -> str:
        cleaned = str(value or "").strip()
        digits = re.sub(r"\D", "", cleaned)
        if digits.startswith("1") and len(digits) == 11:
            digits = digits[1:]
        if len(digits) == 10:
            return f"+1 ({digits[:3]}) {digits[3:6]}-{digits[6:]}"
        if cleaned.startswith("+1"):
            return cleaned
        if cleaned:
            return f"+1 {cleaned}"
        return cleaned

    @field_validator("phone")
    @classmethod
    def validate_phone(cls, value: str) -> str:
        cleaned = value.strip()
        if not PHONE_PATTERN.match(cleaned):
            raise ValueError("Enter a valid phone number.")
        return cleaned

    @field_validator("crm", mode="before")
    @classmethod
    def normalize_optional(cls, value: str | None) -> str | None:
        return _clean_optional(value)

    @field_validator("crm")
    @classmethod
    def validate_crm(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not ORG_PATTERN.match(value):
            raise ValueError("Contains invalid characters.")
        if len(value) > 120:
            raise ValueError("Keep this under 120 characters.")
        return value

    @classmethod
    def from_form(cls, **raw: Any) -> tuple[CallMeSubmission | None, dict[str, str]]:
        crm = _clean_optional(raw.get("crm"))
        crm_other = _clean_optional(raw.get("crm_other"))
        payload = dict(raw)

        if crm == "other":
            if not crm_other:
                return None, {"crm_other": "Enter the CRM you use."}
            payload["crm"] = crm_other

        payload.pop("crm_other", None)

        try:
            return cls.model_validate(payload), {}
        except ValidationError as exc:
            return None, _validation_errors(exc)
