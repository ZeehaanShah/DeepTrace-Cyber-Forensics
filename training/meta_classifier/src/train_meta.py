"""
DeepTrace — Meta-Classifier Training
Run ONCE after text model is trained:
    cd DeepTrace
    pip install scikit-learn joblib numpy
    python training/meta_classifier/src/train_meta.py
"""
import json, numpy as np, joblib
from pathlib import Path
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold, cross_val_score
from sklearn.metrics import classification_report
from sklearn.calibration import CalibratedClassifierCV

ROOT     = Path(__file__).resolve().parents[3]
M1_DIR   = ROOT/"training"/"module1_url"/"models"
M2_DIR   = ROOT/"training"/"module2_text"/"models"
M3_DIR   = ROOT/"training"/"module3_aidetect"/"models"
META_DIR = ROOT/"training"/"meta_classifier"/"models"
META_DIR.mkdir(parents=True, exist_ok=True)

CLASSES = ["legitimate","phishing","ai_generated"]
FEATURES= ["url_phish_score","text_phish_score","ai_detect_score","url_text_diff","combined_risk"]

def check():
    checks = {
        "xgb_url.pkl":        M1_DIR/"xgb_url.pkl",
        "lgb_url.pkl":        M1_DIR/"lgb_url.pkl",
        "deberta_phish/":     M2_DIR/"deberta_phish",
        "aidetect_config.json": M3_DIR/"aidetect_config.json",
    }
    ok=True
    for lbl,path in checks.items():
        exists=path.exists()
        print(f"  [{'OK  ' if exists else 'MISS'}]  {lbl}")
        if not exists: ok=False
    return ok

def make_data(n=12000,seed=42):
    rng=np.random.default_rng(seed); n3=n//3
    u0=rng.beta(1.5,12,n3); t0=rng.beta(1.5,12,n3); a0=rng.beta(2,6,n3)
    u1=rng.beta(10,1.5,n3); t1=rng.beta(10,1.5,n3); a1=rng.beta(4,6,n3)
    u2=rng.beta(2,10,n3);   t2=rng.beta(2.5,8,n3);  a2=rng.beta(10,1.5,n3)
    rows=[]
    for u,t,a in [(u0,t0,a0),(u1,t1,a1),(u2,t2,a2)]:
        rows.append(np.stack([u,t,a,np.abs(u-t),(u+t)/2],axis=1))
    X=np.vstack(rows).astype(np.float32)
    y=np.array([0]*n3+[1]*n3+[2]*n3,dtype=int)
    idx=rng.permutation(len(X))
    return X[idx],y[idx]

def train():
    print("\n"+"="*55)
    print("DeepTrace — Meta-Classifier Training")
    print("="*55)
    print("\nChecking models...")
    ok=check()
    if not ok:
        print("\n  Text model missing — run 02_text_train.ipynb first")
        print("  Continuing anyway (meta will use rule-based fallback until all models present)\n")

    print("\nGenerating synthetic training data (12,000 samples)...")
    X,y=make_data()
    scaler=StandardScaler(); Xs=scaler.fit_transform(X)

    print("Cross-validating Logistic Regression (5-fold)...")
    lr = LogisticRegression(
    C=1.0,
    max_iter=2000,
    random_state=42,
    solver="lbfgs",
    class_weight="balanced"
)
    cv=StratifiedKFold(n_splits=5,shuffle=True,random_state=42)
    accs=cross_val_score(lr,Xs,y,cv=cv,scoring="accuracy")
    print(f"  CV accuracy: {accs.mean():.4f} +/- {accs.std():.4f}")

    cal=CalibratedClassifierCV(lr,cv=5,method="isotonic")
    cal.fit(Xs,y)
    lr.fit(Xs,y)
    print("\nTraining set report:")
    print(classification_report(y,lr.predict(Xs),target_names=CLASSES))

    joblib.dump(cal,    META_DIR/"meta_lr.pkl")
    joblib.dump(scaler, META_DIR/"meta_scaler.pkl")
    cfg={"feature_names":FEATURES,"classes":CLASSES,
         "cv_acc_mean":float(accs.mean()),"cv_acc_std":float(accs.std())}
    with open(META_DIR/"meta_config.json","w") as f:
        json.dump(cfg,f,indent=2)

    print(f"\nSaved to {META_DIR}:")
    for fp in sorted(META_DIR.iterdir()):
        print(f"  {fp.name}  ({fp.stat().st_size//1024} KB)")
    print("\nNext: cd backend && uvicorn app.main:app --reload --port 8000")

if __name__=="__main__":
    train()
