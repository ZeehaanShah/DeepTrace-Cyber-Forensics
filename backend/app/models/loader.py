"""
DeepTrace — Model Loader (FIXED v2)

Fix 1: ROOT = parents[3] (was parents[4] in older versions)
Fix 2: AutoTokenizer/AutoModel str() for Windows path compat
Fix 3: Explicit folder-exists check for text model
Fix 4: Suppress sklearn version warning for LabelEncoder (cosmetic only)
Fix 5: Store feature_names as list for LightGBM named DataFrame inference
"""
import json, warnings
from pathlib import Path
from loguru import logger

# Suppress sklearn version mismatch warning (harmless — LabelEncoder is stable)
warnings.filterwarnings(
    "ignore",
    message="Trying to unpickle estimator LabelEncoder",
    category=UserWarning,
)

# File is at: DeepTrace/backend/app/models/loader.py
# parents[0] = models/, [1] = app/, [2] = backend/, [3] = DeepTrace/ ← ROOT
ROOT     = Path(__file__).resolve().parents[3]
M1_DIR   = ROOT / "training" / "module1_url"      / "models"
M2_DIR   = ROOT / "training" / "module2_text"     / "models"
M3_DIR   = ROOT / "training" / "module3_aidetect" / "models"
META_DIR = ROOT / "training" / "meta_classifier"  / "models"


class ModelLoader:
    xgb_url        = None
    lgb_url        = None
    url_scaler     = None
    url_config     = {}
    url_feat_names = []   # used by inference.py to build named DataFrame for LightGBM

    text_tokenizer = None
    text_model     = None
    text_config    = {}
    text_device    = "cpu"

    ai_tokenizer   = None
    ai_model       = None
    ai_config      = {}
    ai_device      = "cpu"

    meta_lr        = None
    meta_scaler    = None
    meta_config    = {}

    _status = {}
    _ready  = False

    @classmethod
    def initialize(cls):
        if cls._ready:
            return
        logger.info(f"DeepTrace ROOT = {ROOT}")
        cls._load_url()
        cls._load_text()
        cls._load_ai()
        cls._load_meta()
        cls._ready = True

    @classmethod
    def _load_url(cls):
        try:
            import joblib
            cls.xgb_url    = joblib.load(M1_DIR / "xgb_url.pkl")
            cls.lgb_url    = joblib.load(M1_DIR / "lgb_url.pkl")
            sp = M1_DIR / "url_scaler.pkl"
            cls.url_scaler = joblib.load(sp) if sp.exists() else None
            with open(M1_DIR / "url_model_config.json") as f:
                cls.url_config = json.load(f)
            fn_path = M1_DIR / "feature_names.json"
            if fn_path.exists():
                with open(fn_path) as f:
                    cls.url_feat_names = json.load(f)
            cls._status["url"] = "loaded"
            logger.info(
                f"URL models loaded — AUC={cls.url_config.get('test_auc',0):.4f} "
                f"F1={cls.url_config.get('test_f1',0):.4f} "
                f"threshold={cls.url_config.get('threshold',0.5):.3f}"
            )
        except FileNotFoundError as e:
            cls._status["url"] = f"missing: {Path(e.filename).name}"
            logger.warning(f"URL model missing: {e.filename}")
        except Exception as e:
            cls._status["url"] = f"error: {e}"
            logger.error(f"URL load error: {e}")

    @classmethod
    def _load_text(cls):
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            mp = M2_DIR / "deberta_phish"
            if not mp.exists():
                cls._status["text"] = "missing — run 02_text_train.ipynb on Colab T4"
                logger.warning(f"Text model folder not found at: {mp}")
                return

            mp_str = str(mp)
            cls.text_tokenizer = AutoTokenizer.from_pretrained(mp_str)
            cls.text_model     = AutoModelForSequenceClassification.from_pretrained(mp_str)
            cls.text_device    = "cuda" if torch.cuda.is_available() else "cpu"
            cls.text_model     = cls.text_model.to(cls.text_device).eval()

            cfg = mp / "deeptrace_config.json"
            if cfg.exists():
                with open(cfg) as f:
                    cls.text_config = json.load(f)

            cls._status["text"] = "loaded"
            logger.info(
                f"Text model loaded on {cls.text_device} — "
                f"F1={cls.text_config.get('test_f1', 0):.4f}"
            )
        except FileNotFoundError as e:
            cls._status["text"] = "missing — run 02_text_train.ipynb on Colab T4"
            logger.warning(f"Text model file missing: {e}")
        except Exception as e:
            cls._status["text"] = f"error: {e}"
            logger.error(f"Text load error: {e}")

    @classmethod
    def _load_ai(cls):
        try:
            import torch
            from transformers import AutoTokenizer, AutoModelForSequenceClassification

            cfg_path = M3_DIR / "aidetect_config.json"
            cls.ai_config = {}
            if cfg_path.exists():
                with open(cfg_path) as f:
                    cls.ai_config = json.load(f)

            model_id = cls.ai_config.get("model_id", "Hello-SimpleAI/chatgpt-detector-roberta")
            device   = "cuda" if torch.cuda.is_available() else "cpu"

            logger.info(f"Loading AI detector: {model_id} (~500MB, first run may take a few minutes)...")
            cls.ai_tokenizer = AutoTokenizer.from_pretrained(model_id)
            cls.ai_model     = AutoModelForSequenceClassification.from_pretrained(model_id)
            cls.ai_model     = cls.ai_model.to(device).eval()
            cls.ai_device    = device

            cls._status["aidetect"] = "loaded"
            logger.info(f"AI detector loaded on {device} — pretrained RoBERTa ~97% accuracy")
        except Exception as e:
            cls._status["aidetect"] = f"error: {e}"
            logger.error(f"AI detect load error: {e}")

    @classmethod
    def _load_meta(cls):
        try:
            import joblib
            cls.meta_lr     = joblib.load(META_DIR / "meta_lr.pkl")
            cls.meta_scaler = joblib.load(META_DIR / "meta_scaler.pkl")
            with open(META_DIR / "meta_config.json") as f:
                cls.meta_config = json.load(f)
            cls._status["meta"] = "loaded"
            logger.info("Meta-classifier loaded")
        except FileNotFoundError:
            cls._status["meta"] = "missing — run: python training/meta_classifier/src/train_meta.py"
            logger.warning("Meta-classifier not found")
        except Exception as e:
            cls._status["meta"] = f"error: {e}"
            logger.error(f"Meta load error: {e}")

    @classmethod
    def status(cls):
        return dict(cls._status)
