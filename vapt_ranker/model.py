"""
model.py – Train and use a Random Forest classifier to predict
exploitability likelihood for VAPT findings.

The model is trained on a synthetic dataset that reflects real-world
OWASP/CVE patterns.  A pre-trained model is saved to disk with joblib
so subsequent runs don't need to retrain.

Predicted classes:
  0 – Low exploitability
  1 – Medium exploitability
  2 – High exploitability
  3 – Critical exploitability

The model also exposes predict_proba so we can produce a 0–100
exploitability score.
"""

import os
import logging
from pathlib import Path
from typing import List, Tuple, Optional

import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.model_selection import cross_val_score
from sklearn.metrics import classification_report
import joblib

from .features import finding_to_features, FEATURE_NAMES, findings_to_matrix

logger = logging.getLogger("vapt_ranker.model")

MODEL_PATH = Path(__file__).parent / "trained_model.joblib"

LABEL_NAMES = {0: "Low", 1: "Medium", 2: "High", 3: "Critical"}


# ── Synthetic training data ───────────────────────────────────────────────────

def _generate_training_data() -> Tuple[np.ndarray, np.ndarray]:
    """
    Generate a synthetic training dataset of (features, label) pairs.

    Feature vector indices (from features.py):
      0=severity_score, 1=confidence_score, 2=cve_count, 3=max_cvss,
      4=avg_cvss, 5=param_type_score, 6=method_score, 7=is_injection,
      8=is_auth, 9=is_sensitive_param, 10=path_depth,
      11=has_evidence, 12=param_length, 13=issue_type_score

    Labels: 0=Low, 1=Medium, 2=High, 3=Critical
    """
    rng = np.random.default_rng(42)

    # Helper: jitter values
    def j(val, std=0.3, lo=0.0, hi=None):
        v = val + rng.normal(0, std)
        v = max(lo, v)
        if hi is not None:
            v = min(hi, v)
        return round(v, 2)

    records = []

    # ── Critical: SQL/RCE/SSRF injections with high CVSSv3, sensitive params ──
    for _ in range(120):
        records.append((
            [j(4,0.2,3,4), j(2.8,0.3,2,3), j(8,2,0,20), j(9.5,0.5,7,10),
             j(9.0,0.5,6,10), j(4,0.5,2,4), j(3,0.5,2,3), 1, j(0.7,0.3,0,1),
             j(0.8,0.2,0,1), j(3,1,1,8), 1, j(12,4,3,25), 5],
            3
        ))

    # ── High: XSS, path traversal, auth bypass, IDOR ─────────────────────────
    for _ in range(130):
        records.append((
            [j(3,0.5,2,4), j(2,0.5,1,3), j(5,2,0,15), j(7,1.5,4,9),
             j(6.5,1.5,3,9), j(3,0.8,1,4), j(2,0.8,1,3), j(0.6,0.4,0,1),
             j(0.5,0.4,0,1), j(0.5,0.4,0,1), j(2,1,1,6), j(0.7,0.3,0,1),
             j(8,4,2,20), j(3,0.8,2,5)],
            2
        ))

    # ── Medium: open redirect, CSRF, info disclosure ──────────────────────────
    for _ in range(130):
        records.append((
            [j(2,0.6,1,3), j(1.5,0.5,1,2), j(3,1.5,0,10), j(5,2,2,7),
             j(4.5,2,2,7), j(2.5,0.8,1,4), j(1.5,0.7,1,3), j(0.3,0.3,0,1),
             j(0.3,0.3,0,1), j(0.3,0.3,0,1), j(2,1,1,5), j(0.5,0.4,0,1),
             j(6,3,1,15), j(2,0.8,1,3)],
            1
        ))

    # ── Low: info exposure, headers missing, version disclosure ───────────────
    for _ in range(120):
        records.append((
            [j(1,0.5,0,2), j(1,0.5,0,2), j(1,1,0,5), j(3,2,0,5),
             j(2.5,1.5,0,5), j(1.5,0.6,1,3), j(1,0.5,1,2), 0, 0,
             j(0.1,0.2,0,1), j(1,1,0,4), j(0.3,0.3,0,1), j(5,3,1,12), j(1,0.5,0,2)],
            0
        ))

    # Shuffle
    rng.shuffle(records)
    X = np.array([r[0] for r in records], dtype=float)
    y = np.array([r[1] for r in records], dtype=int)

    # Clip to sane ranges
    X[:, 2] = np.clip(X[:, 2], 0, 20)
    X[:, 3] = np.clip(X[:, 3], 0, 10)
    X[:, 4] = np.clip(X[:, 4], 0, 10)
    X[:, 0] = np.clip(X[:, 0], 0, 4)
    X[:, 1] = np.clip(X[:, 1], 0, 3)
    X[:, 5] = np.clip(X[:, 5], 1, 4)
    X[:, 6] = np.clip(X[:, 6], 1, 3)
    X[:, 13] = np.clip(X[:, 13], 0, 5)

    return X, y


# ── Model building ─────────────────────────────────────────────────────────────

def build_pipeline() -> Pipeline:
    return Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=200,
            max_depth=8,
            min_samples_leaf=3,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )),
    ])


def train(verbose: bool = True) -> Pipeline:
    """Train the model, persist it, and return the pipeline."""
    if verbose:
        print("[*] Generating training data …")

    X, y = _generate_training_data()

    if verbose:
        print(f"[*] Training on {len(X)} synthetic samples …")

    pipeline = build_pipeline()
    pipeline.fit(X, y)

    # Cross-validation score
    if verbose:
        scores = cross_val_score(pipeline, X, y, cv=5, scoring="f1_weighted")
        print(f"[*] CV F1 (weighted): {scores.mean():.3f} ± {scores.std():.3f}")
        y_pred = pipeline.predict(X)
        print("\n--- Training set classification report ---")
        print(classification_report(y, y_pred, target_names=list(LABEL_NAMES.values())))

    joblib.dump(pipeline, MODEL_PATH)
    if verbose:
        print(f"[*] Model saved → {MODEL_PATH}")

    return pipeline


def load_or_train(force_retrain: bool = False, verbose: bool = False) -> Pipeline:
    """Load saved model from disk, or train a new one if missing / forced."""
    if not force_retrain and MODEL_PATH.exists():
        try:
            pipeline = joblib.load(MODEL_PATH)
            logger.debug(f"Loaded model from {MODEL_PATH}")
            return pipeline
        except Exception as exc:
            logger.warning(f"Failed to load model ({exc}); retraining …")

    return train(verbose=verbose)


# ── Inference ─────────────────────────────────────────────────────────────────

def predict(pipeline: Pipeline, findings: List[dict]) -> List[dict]:
    """
    Add ML scores to each finding:
      - exploit_class   : 0-3 label
      - exploit_label   : Low / Medium / High / Critical
      - exploit_score   : 0-100 float (probability × 100 of highest class)
    """
    if not findings:
        return findings

    X = findings_to_matrix(findings)
    labels = pipeline.predict(X)
    probas = pipeline.predict_proba(X)  # shape (N, 4)

    for i, finding in enumerate(findings):
        cls = int(labels[i])
        # exploit_score = weighted sum of class probabilities × class weight
        # This gives a continuous 0-100 score
        weights = np.array([0, 33, 66, 100])
        score = float(np.dot(probas[i], weights / 100) * 100)

        finding["exploit_class"]  = cls
        finding["exploit_label"]  = LABEL_NAMES[cls]
        finding["exploit_score"]  = round(score, 1)
        finding["class_proba"]    = {LABEL_NAMES[j]: round(float(p) * 100, 1)
                                     for j, p in enumerate(probas[i])}

    return findings


def get_feature_importances(pipeline: Pipeline) -> List[Tuple[str, float]]:
    """Return (feature_name, importance) pairs sorted descending."""
    clf = pipeline.named_steps["clf"]
    importances = clf.feature_importances_
    pairs = list(zip(FEATURE_NAMES, importances))
    return sorted(pairs, key=lambda x: x[1], reverse=True)
