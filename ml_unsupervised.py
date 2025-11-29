from __future__ import annotations

from typing import Tuple, Dict, Any

import numpy as np
import pandas as pd

from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

def _threshold_by_contamination(scores: np.ndarray, contamination: float):
    """
    Defines a threshold based on the desired anomaly fraction.
    - scores: array of anomaly_score (higher = more suspicious)
    - contamination: fraction in (0, 0.5] typical, e.g.: 0.05

    Returns (threshold, is_anomaly_array)
    """
    scores = np.asarray(scores)
    # sanitizes contamination
    contamination = float(contamination)
    if contamination <= 0.0:
        # nnever marks anything as anomalous
        return scores.max() + 1e-9, np.zeros_like(scores, dtype=int)
    if contamination >= 1.0:
        # anithing is an anomaly
        return scores.min() - 1e-9, np.ones_like(scores, dtype=int)

    q = 1.0 - contamination
    q = min(max(q, 0.0), 1.0)

    if q <= 0.0:
        threshold = scores.min()
    elif q >= 1.0:
        threshold = scores.max()
    else:
        threshold = np.quantile(scores, q)

    is_anomaly = (scores >= threshold).astype(int)
    return threshold, is_anomaly

def _threshold_by_contamination_and_min(
    scores: np.ndarray,
    contamination: float,
    min_score: float | None = None,
):
    """
    Defines a threshold based on:
    - desired anomaly fraction (contamination, via quantile)
    - and, optionally, an absolute minimum score value (min_score).

    Behavior:
    - if min_score <= 0 or None: uses only the quantile (old behavior);
    - if min_score > 0: threshold = max(quantile, min_score).

    Returns:
      (threshold, is_anomaly_array)
    """
    scores = np.asarray(scores)
    contamination = float(contamination)

    # contamination-based quantile
    if contamination <= 0.0:
        # never mark anything as anomalous
        thr_q = scores.max() + 1e-9
    elif contamination >= 1.0:
        # anything is an anomaly
        thr_q = scores.min() - 1e-9
    else:
        q = 1.0 - contamination
        q = min(max(q, 0.0), 1.0)
        if q <= 0.0:
            thr_q = scores.min()
        elif q >= 1.0:
            thr_q = scores.max()
        else:
            thr_q = np.quantile(scores, q)

    # min_score: se None ou <= 0, ignores (It only maintains the logic of the quantile.)
    use_min = (min_score is not None) and (min_score > 0)
    if use_min:
        threshold = max(thr_q, float(min_score))
    else:
        threshold = thr_q

    is_anomaly = (scores >= threshold).astype(int)
    return threshold, is_anomaly


def _check_X(X: pd.DataFrame) -> pd.DataFrame:
    """
    Validates X (numeric DataFrame), sanitizes values, and returns a copy:
    - keeps only numeric columns
    - replaces inf / -inf with NaN
    - fills NaN with median (fallback 0)
    - removes constant columns
    """
    if not isinstance(X, pd.DataFrame):
        raise TypeError("X must be a pandas DataFrame.")

    if X.shape[0] == 0:
        raise ValueError("X has no rows (empty dataset).")

    numeric_cols = X.select_dtypes(include=["number"]).columns.tolist()
    if len(numeric_cols) == 0:
        raise ValueError("X has no numeric columns.")

    X_num = X[numeric_cols].copy()

    # 1) inf → NaN
    X_num.replace([np.inf, -np.inf], np.nan, inplace=True)

    # 2) NaN → median (fallback 0)
    for col in X_num.columns:
        col_data = X_num[col]
        if col_data.isna().all():
            X_num[col] = 0.0
        else:
            median = col_data.median()
            X_num[col] = col_data.fillna(median)

    # 3) remove constant columns
    nunique = X_num.nunique(dropna=False)
    constant_cols = nunique[nunique <= 1].index.tolist()
    if constant_cols:
        X_num = X_num.drop(columns=constant_cols)

    if X_num.shape[1] == 0:
        raise ValueError("After cleaning, no non-constant numeric features remain.")

    return X_num

def _scores_to_df(
    X: pd.DataFrame,
    anomaly_score: np.ndarray,
    is_anomaly: np.ndarray,
) -> pd.DataFrame:
    """
    Construct a DataFrame of scores with an index equal to X.
    """
    df = pd.DataFrame(
        {
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly.astype(int),
        },
        index=X.index,
    )
    df["rank"] = df["anomaly_score"].rank(method="first", ascending=False).astype(int)
    df = df.sort_values("anomaly_score", ascending=False)
    return df

def run_iforest(
    X: pd.DataFrame,
    *,
    contamination: float = 0.05,
    min_score: float | None = None,
    random_state: int = 42,
    n_estimators: int = 200,
    n_jobs: int = -1,
) -> Tuple[IsolationForest, pd.DataFrame]:
    """
    Executes IsolationForest on X.
    - contamination: target fraction of anomalies (quantile)
    - min_score: if > 0, requires that anomaly_score >= min_score as well
    Returns (iforest_model, df_scores)
    """
    Xc = _check_X(X)

    model = IsolationForest(
        n_estimators=n_estimators,
        contamination="auto",  # Controlled by the fraction
        random_state=random_state,
        n_jobs=n_jobs,
        verbose=0,
    )
    model.fit(Xc)

    raw_scores = model.score_samples(Xc)   # More NEGATIVE = more anomalous
    anomaly_score = -raw_scores            # bigger = more suspicious

    threshold, is_anomaly = _threshold_by_contamination_and_min(
        anomaly_score,
        contamination=contamination,
        min_score=min_score,
    )

    df_scores = _scores_to_df(Xc, anomaly_score, is_anomaly)

    return model, df_scores

def run_lof(
    X: pd.DataFrame,
    *,
    contamination: float = 0.05,
    min_score: float | None = None,
    n_neighbors: int = 20,
    standardize: bool = True,
) -> Tuple[LocalOutlierFactor, pd.DataFrame]:
    """
    Executes LOF on X.
    - contamination: target fraction of anomalies
    - min_score: if > 0, requires anomaly_score >= min_score

    Returns (modelo_lof, df_scores)
    """
    Xc = _check_X(X)

    if Xc.shape[0] <= n_neighbors:
        n_neighbors = max(2, Xc.shape[0] - 1)

    if standardize:
        scaler = StandardScaler()
        Xs = scaler.fit_transform(Xc)
    else:
        scaler = None
        Xs = Xc.values

    # contamination="auto" → LOF doesn't use that parameter for the threshold, it only adjusts the factor.
    lof = LocalOutlierFactor(
        n_neighbors=n_neighbors,
        contamination="auto",
        novelty=False,
    )

    _ = lof.fit_predict(Xs)  # adjust the model and negative_outlier_factor_
    neg_factor = lof.negative_outlier_factor_  # More NEGATIVE = more anomalous
    anomaly_score = -neg_factor                # bigger = more suspicious

    threshold, is_anomaly = _threshold_by_contamination_and_min(
        anomaly_score,
        contamination=contamination,
        min_score=min_score,
    )

    df_scores = _scores_to_df(Xc, anomaly_score, is_anomaly)

    if scaler is not None:
        setattr(lof, "_scaler", scaler)

    return lof, df_scores

def run_kmeans_outlier(
    X: pd.DataFrame,
    *,
    n_clusters: int = 5,
    contamination: float = 0.05,
    min_score: float | None = None,
    random_state: int = 42,
    standardize: bool = True,
) -> Tuple[Dict[str, Any], pd.DataFrame]:
    """
    Use K-means as baseline for outliers:
    - distance to the cluster centroid as anomaly_score.
    - contamination: target fraction of anomalies.
    - min_score: if > 0, requires anomaly_score >= min_score.

    Returns (info, df_scores)
    """
    Xc = _check_X(X)

    if Xc.shape[0] < n_clusters:
        n_clusters = max(1, Xc.shape[0] // 2 or 1)

    if standardize:
        scaler = StandardScaler()
        Xs = scaler.fit_transform(Xc)
    else:
        scaler = None
        Xs = Xc.values

    try:
        kmeans = KMeans(
            n_clusters=n_clusters,
            random_state=random_state,
            n_init="auto",
        )
    except TypeError:
        kmeans = KMeans(
            n_clusters=n_clusters,
            random_state=random_state,
            n_init=10,
        )

    labels = kmeans.fit_predict(Xs)
    centers = kmeans.cluster_centers_

    distances = np.linalg.norm(Xs - centers[labels], axis=1)
    anomaly_score = distances

    threshold, is_anomaly = _threshold_by_contamination_and_min(
        anomaly_score,
        contamination=contamination,
        min_score=min_score,
    )

    df_scores = _scores_to_df(Xc, anomaly_score, is_anomaly)

    info = {
        "kmeans": kmeans,
        "scaler": scaler,
        "threshold": threshold,
        "n_clusters": n_clusters,
        "contamination": contamination,
    }
    return info, df_scores
