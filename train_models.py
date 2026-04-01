"""Train NIDS models from CICIDS CSV or synthetic bootstrap data."""

import argparse
import os
import pandas as pd
import numpy as np
import kagglehub
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from nids_engine.ml.model_manager import ModelManager, FEATURE_COLUMNS

def generate_dummy_benign_data(num_samples: int = 1000) -> pd.DataFrame:
    """Generates synthetic benign network flow features for baseline training."""
    np.random.seed(42)
    
    data = {}
    for col in FEATURE_COLUMNS:
        # Generate basic normal distributions
        if 'Length' in col:
            data[col] = np.random.normal(loc=500, scale=150, size=num_samples)
        elif 'Duration' in col:
            data[col] = np.random.exponential(scale=1.5, size=num_samples)
        elif 'Count' in col or 'Packets' in col:
            data[col] = np.random.poisson(lam=5, size=num_samples)
        else:
            data[col] = np.random.uniform(0, 1000, size=num_samples)
            
    df = pd.DataFrame(data)
    # Ensure no negatives
    df = df.clip(lower=0)
    return df

def load_limited_csv(csv_path: str, max_memory_mb: float = 1200.0) -> pd.DataFrame:
    """Loads a CSV with memory safety. Estimates row size then samples to stay < 1.2GB."""
    # Peek at the data to estimate memory usage per row
    peek_df = pd.read_csv(csv_path, nrows=1000)
    bytes_per_row = peek_df.memory_usage(deep=True).sum() / 1000
    
    # Calculate rows that fit in the limit
    max_rows = int((max_memory_mb * 1024 * 1024) / bytes_per_row)
    # Target up to 5,000,000 rows but honor the memory limit above all
    rows_to_load = min(max_rows, 5000000)
    
    print(f"Memory safety: loading {rows_to_load} rows (estimated {bytes_per_row:.1f} bytes/row) to stay under {max_memory_mb}MB.")
    return pd.read_csv(csv_path, nrows=rows_to_load)


def train_from_cicids_csv(csv_path: str, manager: ModelManager) -> None:
    df = load_limited_csv(csv_path)

    # Detect Label column (standard CIC-IDS uses "Label", but this Kaggle version uses "Attack Type")
    target_col = None
    for possible in ["Label", "Attack Type"]:
        if possible in df.columns:
            target_col = possible
            break
            
    if not target_col:
        raise ValueError(f"Dataset must include a 'Label' or 'Attack Type' column. Found columns: {list(df.columns)}")

    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0.0

    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    X = df[FEATURE_COLUMNS]
    y = df[target_col].astype(str)

    benign_mask = y.str.lower() == "benign"
    if benign_mask.any():
        manager.train_isolation_forest(X[benign_mask], contamination=0.01)

    x_train, x_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.2,
        random_state=42,
        stratify=y if y.nunique() > 1 else None,
    )

    manager.train_random_forest(x_train, y_train)
    y_pred = manager.rf_model.predict(manager.scaler.transform(x_test[FEATURE_COLUMNS]))
    print(classification_report(y_test, y_pred))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train NIDS ML models")
    parser.add_argument("--cicids-csv", type=str, help="Path to CICIDS2017/2018 CSV file")
    parser.add_argument("--samples", type=int, default=5000, help="Synthetic sample count")
    args = parser.parse_args()

    manager = ModelManager()

    if args.cicids_csv:
        dataset_path = args.cicids_csv
    else:
        print("Fetching CICIDS2017 dataset from Kaggle...")
        try:
            k_path = kagglehub.dataset_download("ericanacletoribeiro/cicids2017-cleaned-and-preprocessed")
            csv_files = [f for f in os.listdir(k_path) if f.endswith('.csv')]
            if not csv_files:
                raise FileNotFoundError(f"No CSV files found in {k_path}")
            dataset_path = os.path.join(k_path, csv_files[0])
        except Exception as e:
            print(f"Error fetching Kaggle dataset: {e}")
            print("Falling back to synthetic data generation...")
            df_train = generate_dummy_benign_data(args.samples)
            manager.train_isolation_forest(df_train, contamination=0.01)
            print(f"Models saved to {manager.model_dir}")
            exit(0)

    print(f"Training models from: {dataset_path}")
    train_from_cicids_csv(dataset_path, manager)
    
    print(f"Models saved to {manager.model_dir}")
