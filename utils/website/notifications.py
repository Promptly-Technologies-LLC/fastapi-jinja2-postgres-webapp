"""Email notifications for website lead forms."""

from __future__ import annotations

import logging
import os

import resend

from utils.website.content import (
    DEMO_PHONE_ANSWERERS,
    DEMO_TECHNICIAN_COUNTS,
    WEBSITE_CONTACT_EMAIL,
)
from utils.website.forms import BookDemoSubmission, CallMeSubmission

logger = logging.getLogger("uvicorn.error")


def _option_label(options: list[tuple[str, str]], value: str | None) -> str | None:
    if not value:
        return None
    for option_value, option_label in options:
        if option_value == value:
            return option_label
    return value


def _leads_notify_email() -> str:
    return os.getenv("LEADS_NOTIFY_EMAIL", WEBSITE_CONTACT_EMAIL)


def _send_html_email(subject: str, html: str) -> bool:
    api_key = os.getenv("RESEND_API_KEY")
    email_from = os.getenv("EMAIL_FROM")
    if not api_key or not email_from:
        logger.warning(
            "Lead notification skipped: RESEND_API_KEY or EMAIL_FROM not configured."
        )
        return False

    resend.api_key = api_key
    params = {
        "from": email_from,
        "to": [_leads_notify_email()],
        "subject": subject,
        "html": html,
    }
    try:
        sent = resend.Emails.send(params)  # ty: ignore[invalid-argument-type]
        logger.info("Lead notification sent: %s", sent.get("id"))
        return True
    except Exception:
        logger.exception("Failed to send lead notification email")
        return False


def notify_book_demo(submission: BookDemoSubmission) -> bool:
    optional_rows = ""
    technicians = _option_label(DEMO_TECHNICIAN_COUNTS, submission.technicians)
    phone_answerer = _option_label(DEMO_PHONE_ANSWERERS, submission.phone_answerer)
    if technicians:
        optional_rows += f"<tr><td><strong>Technicians</strong></td><td>{technicians}</td></tr>"
    if phone_answerer:
        optional_rows += (
            f"<tr><td><strong>Who answers phones</strong></td>"
            f"<td>{phone_answerer}</td></tr>"
        )

    html = f"""
    <h2>New demo request</h2>
    <table cellpadding="6" cellspacing="0">
      <tr><td><strong>Email</strong></td><td>{submission.work_email}</td></tr>
      <tr><td><strong>Name</strong></td><td>{submission.first_name} {submission.last_name}</td></tr>
      <tr><td><strong>Company</strong></td><td>{submission.company}</td></tr>
      <tr><td><strong>Trade</strong></td><td>{submission.trade}</td></tr>
      <tr><td><strong>Phone</strong></td><td>{submission.phone}</td></tr>
      {optional_rows}
    </table>
    """
    return _send_html_email(
        f"Demo request — {submission.company}",
        html,
    )


def notify_call_me(submission: CallMeSubmission) -> bool:
    crm_value = submission.crm or "—"
    html = f"""
    <h2>Call-me request</h2>
    <table cellpadding="6" cellspacing="0">
      <tr><td><strong>Name</strong></td><td>{submission.name}</td></tr>
      <tr><td><strong>Company</strong></td><td>{submission.business}</td></tr>
      <tr><td><strong>Email</strong></td><td>{submission.email}</td></tr>
      <tr><td><strong>Phone</strong></td><td>{submission.phone}</td></tr>
      <tr><td><strong>Industry</strong></td><td>{submission.industry}</td></tr>
      <tr><td><strong>CRM</strong></td><td>{crm_value}</td></tr>
    </table>
    <p>Follow up with an outbound Calli demo call when ready.</p>
    """
    return _send_html_email(
        f"Call-me request — {submission.business}",
        html,
    )
