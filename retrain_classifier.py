"""
Script to retrain the Random Forest classifier with CICIDS 2018 dataset
Handles multiple CSV files and merges them for training
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import pickle
from lime import lime_tabular
import dill
import os
import glob
from pathlib import Path

# Column mapping: CICIDS 2018 actual column names to our application names
COLUMN_MAPPING = {
    'Flow Duration': 'FlowDuration',
    'Bwd Pkt Len Max': 'BwdPacketLengthMax',
    'Bwd Pkt Len Min': 'BwdPacketLengthMin',
    'Bwd Pkt Len Mean': 'BwdPacketLengthMean',
    'Bwd Pkt Len Std': 'BwdPacketLengthStd',
    'Flow IAT Mean': 'FlowIATMean',
    'Flow IAT Std': 'FlowIATStd',
    'Flow IAT Max': 'FlowIATMax',
    'Flow IAT Min': 'FlowIATMin',
    'Fwd IAT Tot': 'FwdIATTotal',
    'Fwd IAT Mean': 'FwdIATMean',
    'Fwd IAT Std': 'FwdIATStd',
    'Fwd IAT Max': 'FwdIATMax',
    'Fwd IAT Min': 'FwdIATMin',
    'Bwd IAT Tot': 'BwdIATTotal',
    'Bwd IAT Mean': 'BwdIATMean',
    'Bwd IAT Std': 'BwdIATStd',
    'Bwd IAT Max': 'BwdIATMax',
    'Bwd IAT Min': 'BwdIATMin',
    'Fwd PSH Flags': 'FwdPSHFlags',
    'Fwd Pkts/s': 'FwdPackets/s',
    'Pkt Len Max': 'PacketLengthMax',
    'Pkt Len Mean': 'PacketLengthMean',
    'Pkt Len Std': 'PacketLengthStd',
    'Pkt Len Var': 'PacketLengthVariance',
    'FIN Flag Cnt': 'FINFlagCount',
    'SYN Flag Cnt': 'SYNFlagCount',
    'PSH Flag Cnt': 'PSHFlagCount',
    'ACK Flag Cnt': 'ACKFlagCount',
    'URG Flag Cnt': 'URGFlagCount',
    'Pkt Size Avg': 'AveragePacketSize',
    'Bwd Seg Size Avg': 'BwdSegmentSizeAvg',
    'Init Fwd Win Byts': 'FWDInitWinBytes',
    'Init Bwd Win Byts': 'BwdInitWinBytes',
    'Active Min': 'ActiveMin',
    'Idle Mean': 'IdleMean',
    'Idle Std': 'IdleStd',
    'Idle Max': 'IdleMax',
    'Idle Min': 'IdleMin'
}

# Required features (39 total)
REQUIRED_FEATURES = [
    'FlowDuration', 'BwdPacketLengthMax', 'BwdPacketLengthMin',
    'BwdPacketLengthMean', 'BwdPacketLengthStd', 'FlowIATMean',
    'FlowIATStd', 'FlowIATMax', 'FlowIATMin', 'FwdIATTotal',
    'FwdIATMean', 'FwdIATStd', 'FwdIATMax', 'FwdIATMin',
    'BwdIATTotal', 'BwdIATMean', 'BwdIATStd', 'BwdIATMax',
    'BwdIATMin', 'FwdPSHFlags', 'FwdPackets/s', 'PacketLengthMax',
    'PacketLengthMean', 'PacketLengthStd', 'PacketLengthVariance',
    'FINFlagCount', 'SYNFlagCount', 'PSHFlagCount', 'ACKFlagCount',
    'URGFlagCount', 'AveragePacketSize', 'BwdSegmentSizeAvg',
    'FWDInitWinBytes', 'BwdInitWinBytes', 'ActiveMin',
    'IdleMean', 'IdleStd', 'IdleMax', 'IdleMin'
]

def load_multiple_csvs(dataset_folder, max_rows_per_file=None):
    """
    Load and merge multiple CSV files from CICIDS 2018 dataset
    
    Args:
        dataset_folder: Path to folder containing CSV files
        max_rows_per_file: Limit rows per file (for testing, use None for all data)
    """
    print("="*60)
    print("Loading CICIDS 2018 Dataset Files")
    print("="*60)
    
    # Find all CSV files
    csv_files = glob.glob(os.path.join(dataset_folder, "*.csv"))
    
    if not csv_files:
        raise FileNotFoundError(f"No CSV files found in: {dataset_folder}")
    
    print(f"\nFound {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"  - {os.path.basename(f)}")
    
    all_dataframes = []
    
    for csv_file in csv_files:
        print(f"\nLoading: {os.path.basename(csv_file)}")
        try:
            # Load with error handling - force object dtype initially
            df = pd.read_csv(
                csv_file, 
                encoding='utf-8', 
                low_memory=False,
                na_values=['', ' ', 'NaN', 'nan', 'NULL', 'null', 'Infinity', '-Infinity']
            )
            
            # Limit rows if specified (for quick testing)
            if max_rows_per_file:
                df = df.head(max_rows_per_file)
            
            print(f"  Shape: {df.shape}")
            
            if 'Label' in df.columns:
                print(f"  Labels: {df['Label'].value_counts().to_dict()}")
            
            all_dataframes.append(df)
            
        except Exception as e:
            print(f"  ✗ Error loading {csv_file}: {e}")
            continue
    
    if not all_dataframes:
        raise ValueError("No CSV files could be loaded successfully")
    
    # Merge all dataframes
    print("\nMerging all datasets...")
    merged_df = pd.concat(all_dataframes, ignore_index=True)
    print(f"✓ Merged dataset shape: {merged_df.shape}")
    
    return merged_df

def preprocess_dataset(df):
    """
    Clean and preprocess the merged dataset
    """
    print("\n" + "="*60)
    print("Preprocessing Dataset")
    print("="*60)
    
    # Strip whitespace from column names
    df.columns = df.columns.str.strip()
    
    # Check for Label column
    label_col = 'Label'
    if label_col not in df.columns:
        print(f"Available columns: {df.columns.tolist()}")
        raise ValueError(f"Label column '{label_col}' not found in dataset")
    
    print(f"\nLabel distribution:")
    label_counts = df[label_col].value_counts()
    for label, count in label_counts.items():
        print(f"  {label}: {count:,} ({count/len(df)*100:.2f}%)")
    
    # Rename columns to match our application
    print("\nMapping column names...")
    for old_name, new_name in COLUMN_MAPPING.items():
        if old_name in df.columns:
            df.rename(columns={old_name: new_name}, inplace=True)
    
    # Check if we have all required features
    missing_features = [f for f in REQUIRED_FEATURES if f not in df.columns]
    if missing_features:
        print(f"\n✗ Missing features: {missing_features}")
        print(f"Available features: {[c for c in df.columns if c != 'Label']}")
        raise ValueError("Dataset missing required features")
    
    print(f"✓ All {len(REQUIRED_FEATURES)} required features present")
    
    # Extract features and labels
    X = df[REQUIRED_FEATURES]
    y = df[label_col]
    
    # Clean data
    print("\nCleaning data...")
    print(f"  Initial rows: {len(X):,}")
    
    # Replace infinity with NaN
    X = X.replace([np.inf, -np.inf], np.nan)
    
    # Count NaN values
    nan_counts = X.isna().sum()
    if nan_counts.sum() > 0:
        print(f"  NaN values found: {nan_counts[nan_counts > 0].to_dict()}")
    
    # Drop rows with NaN
    valid_indices = X.notna().all(axis=1)
    X = X[valid_indices]
    y = y[valid_indices]
    
    print(f"  After cleaning: {len(X):,} rows ({len(X)/len(df)*100:.1f}% retained)")
    
    # Simplify attack labels (combine similar attacks)
    print("\nSimplifying attack labels...")
    label_mapping = {
        # Benign traffic
        'BENIGN': 'Benign',
        'Benign': 'Benign',
        
        # Botnet attacks
        'Bot': 'Botnet',
        'Botnet': 'Botnet',
        
        # DDoS attacks (note the different naming patterns)
        'DDoS': 'DDoS',
        'DDOS attack-HOIC': 'DDoS',
        'DDOS attack-LOIC-UDP': 'DDoS',
        'DDoS attacks-LOIC-HTTP': 'DDoS',
        
        # DoS attacks
        'DoS GoldenEye': 'DoS',
        'DoS Hulk': 'DoS',
        'DoS Slowhttptest': 'DoS',
        'DoS slowloris': 'DoS',
        'DoS Slowloris': 'DoS',
        'DoS attacks-Hulk': 'DoS',
        'DoS attacks-SlowHTTPTest': 'DoS',
        'DoS attacks-GoldenEye': 'DoS',
        'DoS attacks-Slowloris': 'DoS',
        
        # Brute force attacks
        'FTP-Patator': 'FTP-Patator',
        'FTP-BruteForce': 'FTP-Patator',
        'SSH-Patator': 'SSH-Patator',
        'SSH-Bruteforce': 'SSH-Patator',
        
        # Port scanning / Reconnaissance
        'PortScan': 'Probe',
        'Probe': 'Probe',
        
        # Web attacks
        'Web Attack – Brute Force': 'Web Attack',
        'Web Attack – XSS': 'Web Attack',
        'Web Attack – Sql Injection': 'Web Attack',
        'Brute Force -Web': 'Web Attack',
        'Brute Force -XSS': 'Web Attack',
        'SQL Injection': 'Web Attack',
        'Infilteration': 'Web Attack',
        'Infiltration': 'Web Attack',
        
        # Other
        'Heartbleed': 'DoS'
    }
    
    # Apply mapping
    y_mapped = y.map(label_mapping)
    
    # Count unmapped labels
    unmapped = y[y_mapped.isna()]
    if len(unmapped) > 0:
        print(f"\n⚠️  Warning: {len(unmapped)} rows with unmapped labels:")
        unmapped_counts = unmapped.value_counts()
        for label, count in unmapped_counts.items():
            print(f"  '{label}': {count:,}")
        print("\n  These rows will be removed. Add them to label_mapping if needed.")
    
    # Remove any unmapped labels (including the 'Label' header that appeared as data)
    valid_labels = y_mapped.notna()
    X = X[valid_labels]
    y = y_mapped[valid_labels]
    
    print("\nFinal label distribution:")
    for label, count in y.value_counts().items():
        print(f"  {label}: {count:,} ({count/len(y)*100:.2f}%)")
    
    return X.values, y.values, REQUIRED_FEATURES

def train_random_forest(X_train, y_train, X_test, y_test):
    """
    Train Random Forest classifier with optimized hyperparameters
    """
    print("\n" + "="*60)
    print("Training Random Forest Classifier")
    print("="*60)
    
    print(f"\nTraining set size: {len(X_train):,}")
    print(f"Test set size: {len(X_test):,}")
    
    # Create classifier
    clf = RandomForestClassifier(
        n_estimators=100,        # Number of trees
        max_depth=20,            # Maximum tree depth
        min_samples_split=10,    # Minimum samples to split
        min_samples_leaf=4,      # Minimum samples per leaf
        max_features='sqrt',     # Features to consider per split
        random_state=42,
        n_jobs=-1,               # Use all CPU cores
        verbose=1,
        class_weight='balanced'  # Handle imbalanced classes
    )
    
    print("\nTraining (this may take 5-15 minutes)...")
    clf.fit(X_train, y_train)
    
    # Evaluate
    print("\n" + "="*60)
    print("Evaluation Results")
    print("="*60)
    
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f"\nOverall Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
    
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, zero_division=0))
    
    # Feature importance
    print("\nTop 15 Important Features:")
    feature_importance = pd.DataFrame({
        'feature': REQUIRED_FEATURES,
        'importance': clf.feature_importances_
    }).sort_values('importance', ascending=False).head(15)
    
    for idx, row in feature_importance.iterrows():
        print(f"  {row['feature']:30s}: {row['importance']:.4f}")
    
    return clf

def create_lime_explainer(X_train, class_names):
    """
    Create LIME explainer for model interpretability
    """
    print("\n" + "="*60)
    print("Creating LIME Explainer")
    print("="*60)
    
    # Ensure X_train is purely numeric and contiguous
    print("  Preparing data for LIME...")
    
    # Convert to float64 numpy array (force contiguous memory layout)
    X_train_clean = np.ascontiguousarray(X_train, dtype=np.float64)
    
    # Verify no non-numeric values remain
    if not np.isfinite(X_train_clean).all():
        print("  Warning: Found non-finite values, replacing with 0")
        X_train_clean = np.nan_to_num(X_train_clean, nan=0.0, posinf=0.0, neginf=0.0)
    
    # Sample data if too large (LIME can be slow with huge datasets)
    if len(X_train_clean) > 10000:
        print(f"  Sampling 10,000 rows from {len(X_train_clean):,} for LIME training")
        np.random.seed(42)
        sample_indices = np.random.choice(len(X_train_clean), 10000, replace=False)
        X_train_clean = X_train_clean[sample_indices]
    
    print(f"  Creating explainer with {len(X_train_clean):,} samples...")
    print(f"  Data shape: {X_train_clean.shape}, dtype: {X_train_clean.dtype}")
    
    try:
        explainer = lime_tabular.LimeTabularExplainer(
            X_train_clean,
            feature_names=REQUIRED_FEATURES,
            class_names=class_names,
            discretize_continuous=True,
            kernel_width=5,
            mode='classification'
        )
        print("✓ LIME explainer created successfully")
        
    except Exception as e:
        print(f"✗ LIME creation failed: {e}")
        print("\n  Creating simplified explainer without discretization...")
        
        # Fallback: create explainer without discretization
        explainer = lime_tabular.LimeTabularExplainer(
            X_train_clean,
            feature_names=REQUIRED_FEATURES,
            class_names=class_names,
            discretize_continuous=False,  # Disable problematic discretization
            kernel_width=5,
            mode='classification'
        )
        print("✓ Simplified LIME explainer created (no discretization)")
    
    return explainer

def save_models(classifier, explainer):
    """
    Save the trained models
    """
    print("\n" + "="*60)
    print("Saving Models")
    print("="*60)
    
    os.makedirs('models', exist_ok=True)
    
    # Backup old model if exists
    if os.path.exists('models/model.pkl'):
        import shutil
        backup_path = 'models/model.pkl.backup'
        shutil.copy2('models/model.pkl', backup_path)
        print(f"✓ Backed up old model to: {backup_path}")
    
    # Save classifier with joblib
    joblib.dump(classifier, 'models/model.pkl')
    print("✓ Saved classifier to: models/model.pkl")
    
    # Save explainer with dill
    with open('models/explainer', 'wb') as f:
        dill.dump(explainer, f)
    print("✓ Saved explainer to: models/explainer")
    
    # Verify loading
    try:
        test_clf = joblib.load('models/model.pkl')
        with open('models/explainer', 'rb') as f:
            test_exp = dill.load(f)
        print("✓ Verified: Models load successfully")
    except Exception as e:
        print(f"✗ Warning: Model verification failed: {e}")

def main():
    """
    Main training pipeline
    """
    print("="*70)
    print(" "*15 + "CICIDS 2018 Model Training")
    print("="*70)
    
    # CONFIGURATION - UPDATE THIS PATH
    dataset_folder = r'D:\Datasets\CICIDS2018'  # <-- CHANGE THIS TO YOUR PATH
    
    # For quick testing, limit rows per file (set to None for full dataset)
    max_rows_per_file = None  # Use None for production, or 50000 for testing
    
    try:
        # Step 1: Load multiple CSV files
        df = load_multiple_csvs(dataset_folder, max_rows_per_file)
        
        # Step 2: Preprocess
        X, y, feature_names = preprocess_dataset(df)
        
        # Step 3: Split data
        print("\n" + "="*60)
        print("Splitting Dataset")
        print("="*60)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, 
            test_size=0.2, 
            random_state=42, 
            stratify=y
        )
        print(f"✓ Train: {len(X_train):,} | Test: {len(X_test):,}")
        
        # Step 4: Train
        classifier = train_random_forest(X_train, y_train, X_test, y_test)
        
        # Step 5: Create explainer
        class_names = sorted(list(set(y)))
        explainer = create_lime_explainer(X_train, class_names)
        
        # Step 6: Save
        save_models(classifier, explainer)
        
        print("\n" + "="*70)
        print("✓ TRAINING COMPLETE!")
        print("="*70)
        print("\nYou can now run the application:")
        print("  python application.py")
        print("\nThe web interface will be available at:")
        print("  http://localhost:5000")
        
    except FileNotFoundError as e:
        print(f"\n✗ Error: {e}")
        print("\nSetup Instructions:")
        print("1. Download CICIDS 2018 from:")
        print("   https://www.unb.ca/cic/datasets/ids-2018.html")
        print("2. Extract all CSV files to a folder")
        print("3. Update 'dataset_folder' in this script (line 238)")
        print(f"   Current path: {dataset_folder}")
        
    except Exception as e:
        print(f"\n✗ Error during training: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()