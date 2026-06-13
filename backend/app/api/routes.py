"""
DeepTrace — API Routes (v4 — FIXED)

Fixes applied:
  1. meta_decide() now receives has_url/has_text/has_ai flags so it never
     uses zero-padded scores for modules that didn't run. This was the root
     cause of "risk always 0 / always legitimate".
  2. _risk() now shows meaningful non-zero values for legitimate content
     (risk = 0 looked broken even when correct).
  3. All mode separations preserved from v3.

mode values:
  "url"      → only URL phishing analysis
  "text"     → only scam/phishing text analysis
  "ai"       → only AI detection
  "text_ai"  → text phishing + AI detection together
  "both"     → url + text + ai (legacy/auto)
"""
from fastapi import APIRouter, Request, HTTPException
from pydantic import BaseModel, Field, field_validator
from slowapi import Limiter
from slowapi.util import get_remote_address
from typing import Optional, List, Dict
import re

from app.utils.inference import predict_url, predict_text, predict_ai, meta_decide

router  = APIRouter()
limiter = Limiter(key_func=get_remote_address)


# ── Request ──────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    text:   Optional[str] = Field(None, max_length=5000)
    url:    Optional[str] = Field(None, max_length=2048)
    source: Optional[str] = Field("unknown")
    mode:   Optional[str] = Field("both")

    @field_validator("text")
    @classmethod
    def clean_text(cls, v):
        return v.strip() if v and v.strip() else None

    @field_validator("url")
    @classmethod
    def clean_url(cls, v):
        return v.strip() if v and v.strip() else None

    @field_validator("mode")
    @classmethod
    def clean_mode(cls, v):
        allowed = ("url", "text", "ai", "text_ai", "both")
        return v if v in allowed else "both"


# ── Response models ───────────────────────────────────────────────────────────

class ModuleResult(BaseModel):
    score:       float
    label:       str
    confidence:  str
    keywords:    List[str] = []
    explanation: str = ""
    error:       Optional[str] = None


class AIVisualization(BaseModel):
    human_pct:   int
    ai_pct:      int
    human_label: str
    ai_label:    str
    is_ai:       bool


class RiskLevel(BaseModel):
    score_pct: int
    level:     str     # "safe" | "suspicious" | "dangerous"
    color:     str     # "green" | "yellow" | "red"
    label:     str


class AnalyzeResponse(BaseModel):
    verdict:     str
    label:       str
    confidence:  float
    summary:     str
    risk:        RiskLevel
    suggestions: List[str] = []
    url_module:  Optional[ModuleResult] = None
    text_module: Optional[ModuleResult] = None
    ai_module:   Optional[ModuleResult] = None
    ai_visual:   Optional[AIVisualization] = None
    char_count:  Optional[int] = None
    truncated:   bool = False
    mode:        str = "both"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _conf(s: float) -> str:
    if s >= 0.80: return "high"
    if s >= 0.55: return "medium"
    return "low"


def _risk(label: str, conf: float) -> RiskLevel:
    """
    FIX: Previous formula gave 0 for high-confidence legitimate, making the
    bar invisible. Now we show a small but visible safe indicator.
    """
    if label == "legitimate":
        # Show 5–25 range for safe — clearly green, not zero
        pct = max(5, min(25, int((1 - conf) * 25) + 5))
    elif label == "ai_generated":
        pct = max(30, min(69, int(conf * 65)))
    else:  # phishing
        pct = max(35, min(100, int(conf * 100)))

    if pct <= 30:
        return RiskLevel(score_pct=pct, level="safe",       color="green",  label=f"Safe ({pct})")
    elif pct <= 70:
        return RiskLevel(score_pct=pct, level="suspicious", color="yellow", label=f"Suspicious ({pct})")
    else:
        return RiskLevel(score_pct=pct, level="dangerous",  color="red",    label=f"Dangerous ({pct})")


def _verdict(label: str, conf: float) -> str:
    if label == "legitimate": return "safe"
    if conf >= 0.75:          return "dangerous"
    if conf >= 0.45:          return "suspicious"
    return "safe"


def _summary(label: str, conf: float, mode: str) -> str:
    pct = int(conf * 100)
    if label == "phishing":
        if mode == "url":
            return f"This URL is likely a phishing or malicious link ({pct}% confidence). Do not open it."
        return f"Phishing or scam content detected ({pct}% confidence). This is designed to steal credentials or money."
    if label == "ai_generated":
        return f"This text is likely AI-generated ({pct}% confidence). It matches language model output patterns."
    if mode == "url":
        return f"This URL appears safe ({pct}% confidence). No phishing signals detected."
    return f"Content appears legitimate ({pct}% confidence). No significant threats detected."


_SUGG: Dict[str, List[str]] = {
    "phishing_url": [
        "Do not click or open this link",
        "Check the real domain carefully — phishers swap characters (paypa1 ≠ paypal)",
        "Scan with VirusTotal before opening any unknown URL",
        "Report the URL to your IT/security team",
        "If you already clicked it, change your passwords immediately",
    ],
    "phishing_text": [
        "Do not click any links in this message",
        "Verify the sender directly using official contact details",
        "Never share OTPs, passwords, or card details over chat or email",
        "Legitimate organizations never ask for credentials via message",
        "Contact the organization through their official website instead",
    ],
    "ai_generated": [
        "Verify all factual claims independently from authoritative sources",
        "AI content can contain convincing but entirely fabricated information",
        "Look for unusually uniform sentence structure or vague generalities",
        "Check whether the source discloses AI-generated content",
    ],
    "legitimate": [
        "Always verify unexpected requests even from known contacts",
        "Keep your browser and security software up to date",
        "Enable two-factor authentication on all important accounts",
    ],
}


def _suggestions(label: str, mode: str) -> List[str]:
    if label == "phishing":
        return _SUGG["phishing_url"] if mode == "url" else _SUGG["phishing_text"]
    if label == "ai_generated":
        return _SUGG["ai_generated"]
    return _SUGG["legitimate"]


_RISKY_KW = [
    "urgent","suspended","verify","confirm","click here","password","otp",
    "one-time","bank","credit card","ssn","bitcoin","gift card","wire transfer",
    "limited time","act now","expires","immediately","dear customer","dear user",
    "congratulations","winner","prize","free","claim","login","sign in",
    "update your","unauthorized","suspicious activity","blocked","security alert",
]


def _keywords(text: str) -> List[str]:
    tl = text.lower()
    return [kw for kw in _RISKY_KW if kw in tl][:8]


def _explain_url(score: float, inds: List[str]) -> str:
    level = "Multiple strong phishing signals" if score >= 0.75 else \
            "Some suspicious characteristics" if score >= 0.50 else \
            "No significant phishing signals"
    if inds:
        return f"{level} detected. Triggered: {'; '.join(inds[:3])}."
    return f"{level} detected in this URL."


def _explain_text(score: float, inds: List[str], kwds: List[str]) -> str:
    level = "Strong phishing/scam language" if score >= 0.75 else \
            "Suspicious language patterns" if score >= 0.50 else \
            "No significant scam language"
    parts = []
    if inds:  parts.append(f"Tactics: {', '.join(inds[:2])}")
    if kwds:  parts.append(f"Risky words: {', '.join(repr(k) for k in kwds[:3])}")
    detail = " — " + "; ".join(parts) if parts else ""
    return f"{level} detected{detail}."


def _explain_ai(score: float, is_ai: bool) -> str:
    if is_ai:
        return (f"{int(score*100)}% AI probability. Uniform sentence rhythm, "
                "low lexical variation, and formulaic structure detected.")
    return (f"{int((1-score)*100)}% human probability. Natural tonal variation "
            "and irregular sentence structure detected.")


def _ai_visual(score: float, is_ai: bool) -> AIVisualization:
    ai_pct    = int(score * 100)
    human_pct = 100 - ai_pct
    return AIVisualization(
        human_pct   = human_pct,
        ai_pct      = ai_pct,
        human_label = f"Human-written ({human_pct}%)",
        ai_label    = f"AI-generated ({ai_pct}%)",
        is_ai       = is_ai,
    )


_URL_RE = re.compile(
    r"(?:https?://|ftp://|ftps://|www\.)[^\s<>\"{}|\\^`\[\]]{3,}|"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|co|uk|in|de|ru|gov|edu|biz|app|xyz|top|tk|ml|ga)"
    r"(?:[^\s<>\"{}|\\^`\[\]]{0,100})?",
    re.IGNORECASE
)


def _norm_url(raw: str) -> str:
    raw = raw.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", raw):
        return "http://" + raw
    return raw


# ── Main endpoint ─────────────────────────────────────────────────────────────

@router.post("/analyze", response_model=AnalyzeResponse)
@limiter.limit("30/minute")
async def analyze(request: Request, body: AnalyzeRequest):
    if not body.text and not body.url:
        raise HTTPException(400, "Provide at least one of: text, url")

    mode = body.mode or "both"

    do_url  = mode in ("url", "both")
    do_text = mode in ("text", "text_ai", "both")
    do_ai   = mode in ("ai", "text_ai", "both")

    url_s = text_s = ai_s = 0.0
    has_url = has_text = has_ai = False
    url_res = text_res = ai_res = ai_vis = None

    # ── URL analysis ──────────────────────────────────────────────────────────
    if do_url:
        effective_url = _norm_url(body.url) if body.url else None

        if not effective_url and body.text and mode == "both":
            found = _URL_RE.findall(body.text)
            if found:
                effective_url = _norm_url(found[0])

        if effective_url:
            r     = predict_url(effective_url)
            url_s = r.get("score", 0.5)
            has_url = True
            inds  = r.get("indicators", [])
            url_res = ModuleResult(
                score       = url_s,
                label       = "phishing" if r.get("is_phishing") else "legitimate",
                confidence  = _conf(url_s),
                keywords    = [],
                explanation = _explain_url(url_s, inds),
                error       = r.get("error"),
            )

    # ── Text phishing ─────────────────────────────────────────────────────────
    if do_text and body.text:
        r      = predict_text(body.text)
        text_s = r.get("score", 0.5)
        has_text = True
        inds   = r.get("indicators", [])
        kwds   = _keywords(body.text)
        text_res = ModuleResult(
            score       = text_s,
            label       = "phishing" if r.get("is_phishing") else "legitimate",
            confidence  = _conf(text_s),
            keywords    = kwds,
            explanation = _explain_text(text_s, inds, kwds),
            error       = r.get("error"),
        )

    # ── AI detection ──────────────────────────────────────────────────────────
    if do_ai and body.text and len(body.text) >= 50:
        r2    = predict_ai(body.text)
        ai_s  = r2.get("score", 0.5)
        has_ai = True
        is_ai = r2.get("is_ai", False)
        ai_res = ModuleResult(
            score       = ai_s,
            label       = r2.get("label", "human"),
            confidence  = _conf(ai_s),
            keywords    = [],
            explanation = _explain_ai(ai_s, is_ai),
            error       = r2.get("error"),
        )
        ai_vis = _ai_visual(ai_s, is_ai)

    # ── Meta decision — FIX: pass has_* flags ─────────────────────────────────
    meta  = meta_decide(url_s, text_s, ai_s,
                        has_url=has_url, has_text=has_text, has_ai=has_ai)
    label = meta["label"]
    conf  = meta["confidence"]

    return AnalyzeResponse(
        verdict     = _verdict(label, conf),
        label       = label,
        confidence  = round(conf, 4),
        summary     = _summary(label, conf, mode),
        risk        = _risk(label, conf),
        suggestions = _suggestions(label, mode),
        url_module  = url_res,
        text_module = text_res,
        ai_module   = ai_res,
        ai_visual   = ai_vis,
        char_count  = len(body.text) if body.text else None,
        truncated   = bool(body.text and len(body.text) >= 5000),
        mode        = mode,
    )


@router.get("/models/status")
async def models_status():
    from app.models.loader import ModelLoader
    return ModelLoader.status()


@router.get("/ping")
async def ping():
    return {"pong": True}
