"""Copy and structured content for the public Calliflowr website."""

from __future__ import annotations

from typing import Any, TypedDict


class CrewCard(TypedDict):
    id: str
    genre: str
    label: str
    placeholder: str
    rotate: float
    offset: bool
    image_src: str | None


class FaqItem(TypedDict):
    question: str
    answer: str


class AgentFeature(TypedDict):
    symbol: str
    bold: str
    text: str


class AgentCard(TypedDict):
    id: str
    name: str
    role: str
    channels: str
    letter: str
    variant: str  # "live" | "in_pilot" | "coming_soon"
    description: str
    features: list[AgentFeature]
    cta_label: str
    cta_href: str
    status_label: str | None


WEBSITE_CONTACT_PHONE = "+1 (518) 608-8150"
WEBSITE_CONTACT_PHONE_TEL = "+15186088150"
WEBSITE_CONTACT_EMAIL = "hello@calliflowr.com"

SHOW_DEMO_GUARANTEE = True

DEMO_TRADES = [
    "HVAC",
    "Plumbing",
    "Electrical",
    "General contracting",
    "Other",
]

def _labeled_options(
    labels: list[str],
    *,
    include_blank: bool = True,
    blank_label: str = "Select…",
) -> list[tuple[str, str]]:
    options: list[tuple[str, str]] = []
    if include_blank:
        options.append(("", blank_label))
    options.extend((label, label) for label in labels)
    return options


DEMO_TRADE_OPTIONS = _labeled_options(DEMO_TRADES, include_blank=False)

DEMO_TECHNICIAN_COUNTS = [
    ("", "Select…"),
    ("1", "1"),
    ("2-5", "2–5"),
    ("6-10", "6–10"),
    ("11-25", "11–25"),
    ("26+", "26+"),
]

DEMO_PHONE_ANSWERERS = [
    ("", "Select…"),
    ("office_voicemail", "Office staff, voicemail after hours"),
    ("owner", "Owner answers"),
    ("answering_service", "Answering service"),
    ("voicemail_only", "Voicemail only"),
    ("other", "Other"),
]

DEMO_METRICS = [
    {
        "value": "1 ring",
        "label": "Every call picked up before the second ring",
    },
    {
        "value": "24/7",
        "label": "Nights, weekends, and mid-rush — never closed",
    },
    {
        "value": "1 day",
        "label": "From signup to answering your line",
    },
]

DEMO_ON_POINTS = [
    "Hear Calli take a real trades call — emergency and all",
    "See the call log and the booking email your office gets",
    "Founding-shop pricing and straight answers — from a founder, not a rep",
]

# Set to a static path when screenshots are added, e.g. "img/website/screenshots/shot-dashboard.png"
DASHBOARD_SCREENSHOT: str | None = "img/website/how-it-works/step-2.png"
EMAIL_SCREENSHOT: str | None = "img/website/how-it-works/step-3.png"


CREW_CARDS: list[CrewCard] = [
    {
        "id": "hvac",
        "genre": "HVAC",
        "label": "HVAC · Albany",
        "placeholder": "HVAC tech at work",
        "rotate": 1.2,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-hvac.jpg",
    },
    {
        "id": "plumber",
        "genre": "Plumbing",
        "label": "Plumbing · Troy",
        "placeholder": "Plumber on site",
        "rotate": -1.5,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-plumbing.jpg",
    },
    {
        "id": "electric",
        "genre": "Electrical",
        "label": "Electrical · Saratoga Springs",
        "placeholder": "Electrician at the panel",
        "rotate": -1.0,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-electrical.jpg",
    },
    {
        "id": "roofing",
        "genre": "Roofing",
        "label": "Roofing · Albany",
        "placeholder": "Roofer on a pitch",
        "rotate": -1.3,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-roofing.jpg",
    },
    {
        "id": "garage",
        "genre": "Garage Door",
        "label": "Garage Door · Latham",
        "placeholder": "Garage door install",
        "rotate": -1.2,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-garage-door.jpg",
    },
    {
        "id": "construction",
        "genre": "Construction",
        "label": "Construction · Schenectady",
        "placeholder": "Crew on a job site",
        "rotate": 1.4,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-construction.jpg",
    },
    {
        "id": "pest",
        "genre": "Pest Control",
        "label": "Pest Control · Utica",
        "placeholder": "Tech at the front door",
        "rotate": 1.0,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-pest-control.jpg",
    },
    {
        "id": "solar",
        "genre": "Solar",
        "label": "Solar · Troy",
        "placeholder": "Solar panel install",
        "rotate": 1.1,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-solar.jpg",
    },
    {
        "id": "cleaning",
        "genre": "Cleaning",
        "label": "Cleaning · Saratoga Springs",
        "placeholder": "Cleaning crew at work",
        "rotate": -0.9,
        "offset": False,
        "image_src": "img/website/hero/calliflowr-cleaning.jpg",
    },
]

CALL_ME_INDUSTRIES = [f"{card['genre']} Services" for card in CREW_CARDS]
CALL_ME_INDUSTRY_OPTIONS = _labeled_options(CALL_ME_INDUSTRIES)

# Popular platforms first, then the rest A–Z (shorter names first within ties), Other last.
CALL_ME_CRM_POPULAR = [
    "ServiceTitan",
    "Housecall Pro",
    "Jobber",
    "Service Fusion",
    "HubSpot",
    "Salesforce",
]
CALL_ME_CRM_REST = sorted(
    [
        "AccuLynx",
        "Clypboard",
        "FieldEdge",
        "FieldPulse",
        "FieldRoutes",
        "JobNimbus",
        "PestPac",
        "Podium",
        "SimPRO",
        "Successware",
        "Workiz",
    ],
    key=lambda name: (name.casefold(), len(name)),
)
CALL_ME_CRMS = CALL_ME_CRM_POPULAR + CALL_ME_CRM_REST
CALL_ME_CRM_OPTIONS = _labeled_options(CALL_ME_CRMS) + [
    ("other", "Custom CRM / Other"),
]

FOOTER_INDUSTRIES = [
    "HVAC",
    "Solar",
    "Roofing",
    "Cleaning",
    "Plumbing",
    "Electrical",
    "Garage Door",
    "Construction",
    "Pest Control",
]

FOOTER_ADDRESS_LINES = [
    "30 3rd St,",
    "Troy, NY 12180",
]

WHERE_NOW = [
    "Albany",
    "Troy",
    "Schenectady",
    "Clifton Park",
    "Latham",
    "Saratoga Springs",
]

WHERE_NEXT = [
    "Glens Falls",
    "Utica",
    "Syracuse",
    "Hudson Valley",
]


FAQ_ITEMS: list[FaqItem] = [
    {
        "question": "Will customers know it's AI?",
        "answer": (
            "When asked our agent's simply reply they are the AI CSR agents for your shop. "
        ),
    },
    {
        "question": "What happens when they agents don't know the answer?",
        "answer": (
            "Our agents don't guess beyond the information provided for them. They take the details, tell the customer the office will follow up and logs it as a lead in your dashboard. "
        ),
        
    },
    {
        "question": "Can the agents quote prices?",
        "answer": (
            "The agents only quotes prices they are given. The rest are booked as an estimate visit or takes details for aa callback, based on rules you set during setup. "
        ),
    },
    {
        "question": "What about emergencies?",
        "answer": (
            "Our agents are trained to flag urgent calls and reach your on-call technicians in under a minute, "
            "by phone and text, with the details already written out."
        ),
    },
    {
        "question": "We already have an answering service.",
        "answer": (
            "Then you're paying to have messages taken. Our agents check for your availability and book the job while the "
            "customer's still on the line."
        ),
    },
    {
        "question": "Do I keep my number? What do I install?",
        "answer": (
            "Yes, and nothing. We forward your existing line, same number and "
            "caller ID, no hardware installation."
        ),
    },
    {
        "question": "What's the setup and cost?",
        "answer": (
            "Our team trains the AI agents on your business and service logic alongside you and mostly deliver within 2 days depending on the complexity. "
        
        ),
    },
]


AGENTS: list[AgentCard] = [
    {
        "id": "inbound",
        "name": "Inbound Agent",
        "role": "Lead answering",
        "channels": "Voice + SMS",
        "letter": "I",
        "variant": "live",
        "description": (
            "Never miss a call, day or night. Every inbound call answered and every "
            "job booked, even when the whole crew is out or the front-office is busy."
        ),
        "features": [
            {
                "symbol": "✓",
                "bold": "Answers in one ring, 24/7.",
                "text": " No voicemail, no hold music.",
            },
            {
                "symbol": "✓",
                "bold": "Books the job",
                "text": " on your calendar and texts the customer a confirmation.",
            },
            {
                "symbol": "✓",
                "bold": "Reaches your on-call tech",
                "text": " in under a minute on emergencies.",
            },
            {
                "symbol": "✓",
                "bold": "Screens spam and takes 20 calls at once.",
                "text": " Let us handle the pressure in a cold snap.",
            },
        ],
        "cta_label": "Hear it take a call →",
        "cta_href": "#call-me",
        "status_label": "Live now",
    },
    {
        "id": "outbound",
        "name": "Outbound Agent",
        "role": "Fill the board",
        "channels": "Voice + SMS",
        "letter": "O",
        "variant": "in_pilot",
        "description": (
            "Fill the board when the phones go quiet. It works your customer "
            "list, so open slots turn into booked work."
        ),
        "features": [
            {
                "symbol": "○",
                "bold": "Happy calls",
                "text": " after every job, so good work turns into great reviews.",
            },
            {
                "symbol": "○",
                "bold": "Win-back calls",
                "text": " to past customers when the schedule is light.",
            },
            {
                "symbol": "○",
                "bold": "Estimate follow-ups",
                "text": " on open quotes before they go cold.",
            },
            {
                "symbol": "○",
                "bold": "Tune-up and maintenance reminders",
                "text": " before the season turns.",
            },
        ],
        "cta_label": "",
        "cta_href": "",
        "status_label": "In pilot",
    },
    {
        "id": "speed-to-lead",
        "name": "Speed to Lead",
        "role": "Hot lead response",
        "channels": "Voice + SMS",
        "letter": "S",
        "variant": "coming_soon",
        "description": (
            "Beat the other shop to every hot lead. The moment a lead comes in, our agent "
            "calls and texts before your competitor picks up the phone."
        ),
        "features": [
            {
                "symbol": "○",
                "bold": "Instant response",
                "text": " to Google LSA, Yelp, Angi, and Thumbtack leads.",
            },
            {
                "symbol": "○",
                "bold": "Follows up by call and text",
                "text": " until the lead books.",
            },
            {
                "symbol": "○",
                "bold": "Every lead logged,",
                "text": " so nothing sits unworked.",
            },
        ],
        "cta_label": "",
        "cta_href": "",
        "status_label": "Coming soon",
    },
]


def website_shared_context() -> dict[str, Any]:
    """Context shared across public website pages."""
    return {
        "contact_phone": WEBSITE_CONTACT_PHONE,
        "contact_phone_tel": WEBSITE_CONTACT_PHONE_TEL,
        "contact_email": WEBSITE_CONTACT_EMAIL,
        "footer_industries": FOOTER_INDUSTRIES,
        "footer_address_lines": FOOTER_ADDRESS_LINES,
    }


def website_home_context() -> dict[str, Any]:
    """Template context shared by the public homepage."""
    return {
        **website_shared_context(),
        "crew_cards": CREW_CARDS,
        "faq_items": FAQ_ITEMS,
        "agents": AGENTS,
        "dashboard_screenshot": DASHBOARD_SCREENSHOT,
        "email_screenshot": EMAIL_SCREENSHOT,
        "call_me_industry_options": CALL_ME_INDUSTRY_OPTIONS,
        "call_me_crm_options": CALL_ME_CRM_OPTIONS,
    }


def website_demo_context() -> dict[str, Any]:
    """Template context for the book-a-demo page."""
    return {
        **website_shared_context(),
        "demo_trades": DEMO_TRADES,
        "demo_trade_options": DEMO_TRADE_OPTIONS,
        "demo_technician_counts": DEMO_TECHNICIAN_COUNTS,
        "demo_phone_answerers": DEMO_PHONE_ANSWERERS,
        "demo_metrics": DEMO_METRICS,
        "demo_on_points": DEMO_ON_POINTS,
        "show_demo_guarantee": SHOW_DEMO_GUARANTEE,
    }
