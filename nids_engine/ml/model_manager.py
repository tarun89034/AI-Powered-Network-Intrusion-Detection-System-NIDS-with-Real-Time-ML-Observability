"""
Machine Learning Pipeline Module
Handles training, saving, loading, and predicting using NIDS models.
Supports Random Forest (Supervised) and Isolation Forest (Unsupervised/Anomaly).
"""

import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import Dict, Any, Tuple

# Ordered list of features expected by the model (matches CICIDS structure roughly)
FEATURE_COLUMNS = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "ACK Flag Count"
]

class ModelManager:
    def __init__(self, model_dir: str = "nids_engine/ml/models"):
        self.model_dir = model_dir
        self.scaler_path = os.path.join(model_dir, "scaler.pkl")
        self.rf_model_path = os.path.join(model_dir, "rf_model.pkl")
        self.if_model_path = os.path.join(model_dir, "if_model.pkl")
        
        self.scaler = None
        self.rf_model = None
        self.if_model = None
        
        if not os.path.exists(model_dir):
            os.makedirs(model_dir, exist_ok=True)
            
        self._load_models()

    def _load_models(self):
        """Loads trained models and scaler if they exist on disk."""
        if os.path.exists(self.scaler_path):
            self.scaler = joblib.load(self.scaler_path)
        else:
            self.scaler = StandardScaler()
            
        if os.path.exists(self.rf_model_path):
            self.rf_model = joblib.load(self.rf_model_path)
        if os.path.exists(self.if_model_path):
            self.if_model = joblib.load(self.if_model_path)

    def _prepare_features(self, features_dict: Dict[str, Any]) -> np.ndarray:
        """Converts feature dictionary into a normalized 2D numpy array."""
        df = pd.DataFrame([features_dict])
        
        # Ensure all columns are present
        for col in FEATURE_COLUMNS:
            if col not in df.columns:
                df[col] = 0.0
                
        # Handle Inf/NaNs resulting from division by zero
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        df.fillna(0, inplace=True)
        
        X_df = df[FEATURE_COLUMNS]
        
        # We need a fitted scaler to transform. If not fitted, we bypass or fit on fly (not ideal for prod)
        try:
            X_scaled = self.scaler.transform(X_df)
        except Exception:
            # Scaler not fitted yet, returning raw for now
            X_scaled = X_df.values
            
        return X_scaled

    def train_isolation_forest(self, X_train: pd.DataFrame, contamination: float = 0.01):
        """Trains an Isolation Forest on benign data (unsupervised)."""
        print("Training Scaler & Isolation Forest...")
        self.scaler.fit(X_train[FEATURE_COLUMNS])
        X_scaled = self.scaler.transform(X_train[FEATURE_COLUMNS])
        
        self.if_model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
        self.if_model.fit(X_scaled)
        
        joblib.dump(self.scaler, self.scaler_path)
        joblib.dump(self.if_model, self.if_model_path)
        print("Models saved successfully.")

    def train_random_forest(self, X_train: pd.DataFrame, y_train: pd.Series):
        """Trains a RandomForest classifier for attack type classification."""
        print("Training Scaler & Random Forest...")
        self.scaler.fit(X_train[FEATURE_COLUMNS])
        X_scaled = self.scaler.transform(X_train[FEATURE_COLUMNS])

        self.rf_model = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
            n_jobs=-1,
        )
        self.rf_model.fit(X_scaled, y_train)

        joblib.dump(self.scaler, self.scaler_path)
        joblib.dump(self.rf_model, self.rf_model_path)
        print("RF model saved successfully.")

    def predict(self, features: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Predicts if a flow is malicious.
        Returns: (is_anomaly: bool, attack_type: str)
        """
        X = self._prepare_features(features)
        
        is_anomaly = False
        attack_type = "Benign"
        
        # 1. Isolation Forest Check (Anomaly Detection)
        if self.if_model:
            # IF returns -1 for outliers, 1 for inliers
            pred = self.if_model.predict(X)[0]
            if pred == -1:
                is_anomaly = True
                attack_type = "Anomaly (Zero-Day)"
                
        # 2. Random Forest Check (Supervised Classification) - if implemented
        if self.rf_model and not is_anomaly:
            pred = self.rf_model.predict(X)[0]
            # Normalize label comparison to handle CICIDS variants
            # ("Benign", "BENIGN", "Normal Traffic", etc.)
            pred_lower = str(pred).strip().lower()
            if pred_lower not in ("benign", "normal traffic", "normal"):
                is_anomaly = True
                attack_type = pred
                
        return is_anomaly, attack_type
