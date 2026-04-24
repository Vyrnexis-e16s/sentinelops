# SentinelOps ML

The IDS module's brain. A scikit-learn pipeline (`StandardScaler` + `OneHotEncoder` + `RandomForestClassifier`) trained on NSL-KDD.

## What ships in the repo

- `scripts/train_ids.py` — trainer (works on real NSL-KDD or a synthetic fallback).
- `scripts/test_inference.py` — sanity check that loads the artifact and runs one prediction.
- `artifacts/ids_rf.joblib` — pre-trained pipeline. Built from synthetic development data so the IDS API works without downloading the 200 MB NSL-KDD archive; retrain on NSL-KDD for stronger evaluation.
- `notebooks/eda.ipynb` — exploratory walkthrough of the dataset and feature importances.

## Retraining on real NSL-KDD

```bash
mkdir -p ml/data
cd ml/data
# Download from https://www.unb.ca/cic/datasets/nsl.html — accept the academic-use license
# Place KDDTrain+.txt and KDDTest+.txt here
cd ../..
pip install -r ml/requirements.txt
python ml/scripts/train_ids.py
```

The trainer writes `ml/artifacts/ids_rf.joblib` with this shape:

```python
{
    "model":        sklearn Pipeline,
    "feature_list": [...],   # column order the inference service expects
    "classes":      [...],   # class labels the model can emit
    "trained_at":   "2026-04-23T...",
    "accuracy":     0.998,   # on the held-out 20% split
    "notes":        "Trained on NSL-KDD",
}
```

## Why RandomForest

NSL-KDD is tabular, mixed numeric + categorical, with strongly non-linear class boundaries. Trees handle this well; deep nets are overkill. A 120-tree forest fits in ~2-3 MB compressed and runs single-flow inference in well under 1 ms.

## Limitations

- NSL-KDD is from 2009. It does not represent modern encrypted traffic, container egress, or cloud-native attack patterns. Treat this model as a teaching aid, not a production detector.
- Synthetic-trained artifact accuracy (~80%) is much lower than the real-data accuracy (~99%), because the synthetic distribution is intentionally easy. Retrain on the real dataset before claiming any number.
- We don't ship online learning yet. See `docs/ROADMAP.md`.
