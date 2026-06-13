"""DeepTrace API Tests — run: python backend/tests/test_api.py"""
import sys
try: import requests
except ImportError: print("pip install requests"); sys.exit(1)

BASE="{BASE}"
BASE="http://localhost:8000"
results=[]

def chk(name,ok,detail=""):
    results.append((ok,name))
    print(f"  {'OK  ' if ok else 'FAIL'}  {name}" + (f"  → {detail}" if detail else ""))
    return ok

print("\n"+"="*55+"\nDeepTrace API Tests\n"+"="*55)

print("\n[1] Health")
try:
    r=requests.get(f"{BASE}/health",timeout=10); d=r.json()
    chk("GET /health 200", r.status_code==200)
    chk("status=ok", d.get("status")=="ok")
    models=d.get("models",{})
    for m in ["url","text","aidetect","meta"]:
        chk(f"{m} model", models.get(m)=="loaded", models.get(m,"missing"))
except Exception as e:
    chk("Health",False,str(e))
    print("\n  Backend not running. Start with:")
    print("  cd DeepTrace/backend && uvicorn app.main:app --reload --port 8000")
    sys.exit(1)

print("\n[2] URL phishing")
r=requests.post(f"{BASE}/api/v1/analyze",json={"url":"http://paypa1-secure.xyz/verify?u=victim@evil.tk"},timeout=15)
d=r.json(); s=d.get("url_module",{}).get("score",0)
chk("phishing URL → 200", r.status_code==200)
chk(f"phishing score > 0.5 (got {s:.3f})", s>0.5, f"verdict={d.get('verdict')}")

r=requests.post(f"{BASE}/api/v1/analyze",json={"url":"https://www.google.com"},timeout=15)
d=r.json(); s=d.get("url_module",{}).get("score",1)
chk(f"legit URL score < 0.6 (got {s:.3f})", s<0.6)

print("\n[3] Text scam")
SCAM="URGENT: Your account is suspended. Click to verify: http://bank-secure.xyz/login"
r=requests.post(f"{BASE}/api/v1/analyze",json={"text":SCAM},timeout=20)
d=r.json(); s=d.get("text_module",{}).get("score",0)
chk("scam text → 200", r.status_code==200)
chk(f"scam text score > 0.5 (got {s:.3f})", s>0.5)

LEGIT="Hi John, meeting at 3pm tomorrow. Please bring the Q3 slides."
r=requests.post(f"{BASE}/api/v1/analyze",json={"text":LEGIT},timeout=20)
d=r.json(); s=d.get("text_module",{}).get("score",1)
chk(f"legit text score < 0.5 (got {s:.3f})", s<0.5)

print("\n[4] AI detection")
AI="The implementation of AI methodologies necessitates comprehensive frameworks for synergistic value creation across diverse industry verticals and stakeholder ecosystems."
r=requests.post(f"{BASE}/api/v1/analyze",json={"text":AI},timeout=30)
d=r.json()
chk("AI text → 200", r.status_code==200)
if d.get("ai_module"):
    s=d["ai_module"]["score"]
    chk(f"AI module score returned (got {s:.3f})", isinstance(s,(int,float)))

print("\n[5] Error handling")
chk("empty body → 400",  requests.post(f"{BASE}/api/v1/analyze",json={},timeout=5).status_code==400)
chk("text>5000 → 422",   requests.post(f"{BASE}/api/v1/analyze",json={"text":"x"*6000},timeout=10).status_code==422)

print("\n"+"="*55)
passed=sum(1 for ok,_ in results if ok); failed=sum(1 for ok,_ in results if not ok)
print(f"Results: {passed} passed,  {failed} failed")
if failed:
    for ok,n in results:
        if not ok: print(f"  FAIL  {n}")
else:
    print("All tests passed.")
print("="*55)
