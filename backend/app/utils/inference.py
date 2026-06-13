"""
DeepTrace — Inference Engine (FIXED)

Key fixes:
  1. meta_decide now uses only the scores from modules that actually ran (no zero-padding)
  2. URL feature extraction: use feature names to pass named array so LGBMClassifier warning is fixed
  3. AI model label ordering verified: Hello-SimpleAI label 0=Human, 1=ChatGPT → proba[1] is AI score ✓
  4. Fallback meta decision is more robust when some modules are skipped
"""
import re, math, tldextract
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
import numpy as np
from loguru import logger
from app.models.loader import ModelLoader

MAX_TEXT = 5000
MAX_URL  = 2048


# ── Module 1: URL Phishing ──────────────────────────────────────────────────

def _entropy(s):
    s = str(s)
    if not s: return 0.0
    freq = {c: s.count(c)/len(s) for c in set(s)}
    return -sum(p*math.log2(p) for p in freq.values())

def _safe_port(p):
    try:
        port = p.port
        return int(port is not None and port not in [80,443])
    except: return 0

def _extract_url_features(url: str) -> List[float]:
    try:
        url = str(url).strip()[:MAX_URL]
        if not url or url.lower() in ["nan","none","null",""]: return [0.0]*52
        safe = url if url.startswith(("http://","https://")) else "http://"+url
        parsed = urlparse(safe)
        try:
            ext = tldextract.extract(safe)
            sub,dom,suf = ext.subdomain or "",ext.domain or "",ext.suffix or ""
        except: sub,dom,suf = "","",""
        path=parsed.path or ""; query=parsed.query or ""; nloc=parsed.netloc or ""
        ul=url.lower()
        return [
            len(url),len(dom),len(sub),len(path),len(query),len(nloc),
            url.count("."),url.count("-"),url.count("_"),url.count("/"),
            url.count("?"),url.count("="),url.count("@"),url.count("!"),
            url.count("%"),url.count("+"),url.count("~"),url.count(","),
            url.count("*"),url.count("#"),url.count("$"),url.count("&"),
            sum(c.isdigit() for c in url)/max(len(url),1),
            sum(c.isalpha() for c in url)/max(len(url),1),
            _entropy(dom),_entropy(url),
            int(bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",url))),
            int("@" in url), int("//" in path), int(url.startswith("https")),
            int(bool(sub and sub!="www")), int(len(sub.split("."))>2),
            int(bool(re.search(r"secure|account|update|login|verify|bank|paypal|ebay|amazon",ul))),
            int(bool(re.search(r"free|click|win|prize|offer|discount|bonus",ul))),
            int(bool(re.search(r"\.exe|\.zip|\.rar|\.scr|\.bat",ul))),
            int("-" in dom), int(bool(re.search(r"\d",dom))),
            path.count("/"), len(path.split("/")[-1]),
            int(bool(re.search(r"wp-admin|phishing|hack|malware",path.lower()))),
            len(query.split("&")) if query else 0, len(suf),
            int(suf in ["tk","ml","ga","cf","gq","xyz","top","click","link","pw"]),
            _safe_port(parsed), len(re.findall(r"\d+",dom)),
            int(len(dom)>0 and max(dom.count(c) for c in set(dom))/len(dom)>0.4),
            int(bool(re.search(r"%[0-9a-fA-F]{2}",url))),
            int(bool(re.search(r"google|facebook|apple|microsoft|netflix|instagram|twitter|linkedin",ul)
                and not re.search(r"\.(google|facebook|apple|microsoft|netflix|instagram|twitter|linkedin)\.com$",nloc.lower()))),
            int(bool(re.search(r"bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly",ul))),
            int("xn--" in ul), len(sub.split(".")) if sub else 0,
            int(bool(parsed.fragment)),
        ]
    except: return [0.0]*52

_URL_FLAGS = {
    26:"IP address used as domain", 27:"@ symbol in URL", 29:"Not using HTTPS",
    31:"Deep nested subdomain", 32:"Phishing keywords (login/verify)",
    33:"Spam keywords (free/win/prize)", 34:"Executable extension",
    42:"Suspicious TLD", 46:"URL encoding obfuscation",
    47:"Brand impersonation", 48:"URL shortener", 49:"Punycode domain",
}

def predict_url(url: str) -> Dict[str,Any]:
    ml = ModelLoader
    if ml.xgb_url is None:
        return {"score":0.5,"error":"URL model not loaded","fallback":True}
    try:
        feat_vals = _extract_url_features(url)
        feat_arr  = np.array([feat_vals], dtype=np.float32)
        feat_arr  = np.nan_to_num(feat_arr, nan=0.0, posinf=0.0, neginf=0.0)

        # XGBoost — plain numpy works fine
        xp = float(ml.xgb_url.predict_proba(feat_arr)[0,1])

        # LightGBM — pass pandas DataFrame with feature names to suppress warning
        try:
            import pandas as pd
            feat_df = pd.DataFrame(feat_arr, columns=ml.url_feat_names)
            lp = float(ml.lgb_url.predict_proba(feat_df)[0,1])
        except Exception:
            lp = float(ml.lgb_url.predict_proba(feat_arr)[0,1])

        score  = 0.5*xp + 0.5*lp
        thresh = ml.url_config.get("threshold", 0.52)
        inds   = [_URL_FLAGS[i] for i,v in enumerate(feat_vals) if i in _URL_FLAGS and v>0][:5]
        return {
            "score":       round(score, 4),
            "is_phishing": score >= thresh,
            "xgb_score":   round(xp, 4),
            "lgb_score":   round(lp, 4),
            "threshold":   thresh,
            "indicators":  inds,
        }
    except Exception as e:
        logger.error(f"URL inference: {e}")
        return {"score":0.5,"error":str(e)}


# ── Module 2: Text Phishing ─────────────────────────────────────────────────

_PHISH_PATTERNS = [
    (r"click here.{0,30}(verify|confirm|update)",                    "Click-bait verification link"),
    (r"your (account|card|password).{0,30}(suspended|expired|locked)","Account threat language"),
    (r"(congratulations|you.ve won|you have been selected)",          "Prize or lottery scam"),
    (r"urgent.{0,20}(action|response|attention)",                     "Urgency manipulation"),
    (r"(send|transfer).{0,30}(money|bitcoin|gift card)",              "Payment request"),
    (r"(otp|one.time.password|verification code).{0,30}(share|send|give)","OTP phishing"),
    (r"(dear customer|dear user|dear account holder)",                "Generic mass-phish salutation"),
    (r"(limited time|expires in|act now|respond immediately)",        "Time pressure tactic"),
    (r"(username|password|credit card|ssn).{0,30}(enter|provide|confirm)","Credential harvesting"),
]

def predict_text(text: str) -> Dict[str,Any]:
    if not text or not text.strip():
        return {"score":0.5,"error":"Empty text"}
    text = text[:MAX_TEXT]
    ml   = ModelLoader
    if ml.text_model is None:
        return {"score":0.5,"error":"Text model not loaded — run 02_text_train.ipynb","fallback":True}
    try:
        import torch
        max_len = ml.text_config.get("max_len", 128)
        enc     = ml.text_tokenizer(text, max_length=max_len, padding="max_length",
                                    truncation=True, return_tensors="pt")
        ids  = enc["input_ids"].to(ml.text_device)
        mask = enc["attention_mask"].to(ml.text_device)
        with torch.no_grad():
            logits = ml.text_model(input_ids=ids, attention_mask=mask).logits
            proba  = torch.softmax(logits, dim=-1)[0].cpu().numpy()
        # label 0 = Legitimate, label 1 = Phishing (from training notebook)
        model_score = float(proba[1])
        boost=0.0; inds=[]
        tl=text.lower()
        for pat,lbl in _PHISH_PATTERNS:
            if re.search(pat, tl):
                boost += 0.03; inds.append(lbl)
        final = min(1.0, model_score + boost)
        return {
            "score":        round(final, 4),
            "model_score":  round(model_score, 4),
            "rule_boost":   round(boost, 4),
            "is_phishing":  final >= 0.5,
            "indicators":   inds[:5],
            "char_count":   len(text),
        }
    except Exception as e:
        logger.error(f"Text inference: {e}")
        return {"score":0.5,"error":str(e)}


# ── Module 3: AI Detection ──────────────────────────────────────────────────

def predict_ai(text: str) -> Dict[str,Any]:
    """
    Uses Hello-SimpleAI/chatgpt-detector-roberta (pretrained, ~97% accuracy).
    HuggingFace label mapping: 0 = Human, 1 = ChatGPT/AI
    So proba[1] = AI probability (correct).
    """
    if not text or len(text.strip()) < 20:
        return {"score":0.5,"is_ai":False,"note":"Text too short (min 20 chars)"}
    text = " ".join(text.split())[:MAX_TEXT]
    ml   = ModelLoader
    if ml.ai_model is None:
        return {"score":0.5,"error":"AI model not loaded","fallback":True}
    try:
        import torch
        thresh  = ml.ai_config.get("threshold", 0.5)
        max_len = ml.ai_config.get("max_length", 512)
        enc = ml.ai_tokenizer(text, truncation=True, max_length=max_len, return_tensors="pt")
        enc = {k:v.to(ml.ai_device) for k,v in enc.items()}
        with torch.no_grad():
            logits = ml.ai_model(**enc).logits
            proba  = torch.softmax(logits, dim=-1)[0].cpu().numpy()

        # Verify label ordering from model config
        # Hello-SimpleAI model: id2label = {0: "Human", 1: "ChatGPT"}
        # So index 1 = AI/ChatGPT score
        ai_idx = 1
        # Double-check using model's own id2label if available
        if hasattr(ml.ai_model.config, "id2label") and ml.ai_model.config.id2label:
            id2label = ml.ai_model.config.id2label
            # Find which index corresponds to non-human label
            for idx, lbl in id2label.items():
                if "chatgpt" in str(lbl).lower() or "ai" in str(lbl).lower() or "gpt" in str(lbl).lower():
                    ai_idx = int(idx)
                    break

        ai_score = float(proba[ai_idx])
        return {
            "score":     round(ai_score, 4),
            "is_ai":     ai_score >= thresh,
            "label":     "ai_generated" if ai_score >= thresh else "human",
            "threshold": thresh,
        }
    except Exception as e:
        logger.error(f"AI inference: {e}")
        return {"score":0.5,"error":str(e)}


# ── Meta Decision ───────────────────────────────────────────────────────────

def meta_decide(
    url_s:   float,
    text_s:  float,
    ai_s:    float,
    has_url: bool = False,
    has_text: bool = False,
    has_ai:  bool = False,
) -> Dict[str,Any]:
    """
    FIX: Only use scores from modules that actually ran.
    Passing zeros for skipped modules was biasing the meta-classifier toward 'legitimate'.
    """
    ml      = ModelLoader
    classes = ["legitimate", "phishing", "ai_generated"]

    # ── Rule-based fallback (when meta model not available or as sanity check) ──
    def _rule_based():
        # Only URL ran
        if has_url and not has_text and not has_ai:
            url_thresh = ml.url_config.get("threshold", 0.52) if ml.url_config else 0.52
            if url_s >= url_thresh:
                return {"label":"phishing", "confidence":round(url_s,4), "fallback":True}
            return {"label":"legitimate", "confidence":round(1-url_s,4), "fallback":True}

        # Only Text ran
        if has_text and not has_url and not has_ai:
            text_thresh = 0.50
            if text_s >= text_thresh:
                return {"label":"phishing", "confidence":round(text_s,4), "fallback":True}
            return {"label":"legitimate", "confidence":round(1-text_s,4), "fallback":True}

        # Only AI ran
        if has_ai and not has_url and not has_text:
            ai_thresh = ml.ai_config.get("threshold", 0.50) if ml.ai_config else 0.50
            if ai_s >= ai_thresh:
                return {"label":"ai_generated", "confidence":round(ai_s,4), "fallback":True}
            return {"label":"legitimate", "confidence":round(1-ai_s,4), "fallback":True}

        # Multiple ran
        active_scores = []
        if has_url:  active_scores.append(url_s)
        if has_text: active_scores.append(text_s)

        if has_ai and ai_s >= 0.65:
            # Strong AI signal and not very phishy
            combined = sum(active_scores) / len(active_scores) if active_scores else 0.3
            if combined < 0.45:
                return {"label":"ai_generated", "confidence":round(ai_s,4), "fallback":True}

        if active_scores:
            combined = sum(active_scores) / len(active_scores)
            thresh_used = ml.url_config.get("threshold", 0.52) if has_url else 0.50
            if combined >= thresh_used:
                return {"label":"phishing", "confidence":round(combined,4), "fallback":True}
            else:
                return {"label":"legitimate", "confidence":round(1-combined,4), "fallback":True}

        # Nothing ran — shouldn't happen
        return {"label":"legitimate", "confidence":0.5, "fallback":True}

    # Short-circuit machine learning model if only one module ran
    active_count = sum([has_url, has_text, has_ai])
    if active_count == 1:
        return _rule_based()

    if ml.meta_lr is None:
        return _rule_based()

    try:
        # Build feature vector — use actual module scores
        # For modules that didn't run, use the neutral/uninformative value (0.5)
        # rather than 0.0, which was biasing predictions
        eff_url  = url_s  if has_url  else 0.5
        eff_text = text_s if has_text else 0.5
        eff_ai   = ai_s   if has_ai   else 0.5

        X  = np.array([[eff_url, eff_text, eff_ai,
                         abs(eff_url - eff_text),
                         (eff_url + eff_text) / 2]], dtype=np.float32)
        Xs = ml.meta_scaler.transform(X)
        pr = ml.meta_lr.predict_proba(Xs)[0]
        i  = int(np.argmax(pr))

        # Sanity check: if meta says legitimate but a module score is very high, override
        if classes[i] == "legitimate":
            if has_url  and url_s  >= 0.75: return {"label":"phishing",      "confidence":round(url_s,4)}
            if has_text and text_s >= 0.75: return {"label":"phishing",      "confidence":round(text_s,4)}
            if has_ai   and ai_s   >= 0.80: return {"label":"ai_generated",  "confidence":round(ai_s,4)}

        return {
            "label":         classes[i],
            "confidence":    round(float(pr[i]), 4),
            "probabilities": {c:round(float(p),4) for c,p in zip(classes,pr)},
        }
    except Exception as e:
        logger.error(f"Meta inference: {e}")
        return _rule_based()
