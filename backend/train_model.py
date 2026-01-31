"""
Model Training Script for NSL-KDD Dataset
Run this once: python train_model.py
"""

import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import pickle
import warnings
warnings.filterwarnings('ignore')

def train_nsl_kdd_model():
    """
    Train model on NSL-KDD dataset
    Download from: https://www.kaggle.com/datasets/hassan06/nslkdd
    Files needed: KDDTrain+.txt, KDDTest+.txt
    """
    
    # Column names for NSL-KDD
    column_names = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root', 'num_file_creations',
        'num_shells', 'num_access_files', 'num_outbound_cmds', 'is_host_login',
        'is_guest_login', 'count', 'srv_count', 'serror_rate', 'srv_serror_rate',
        'rerror_rate', 'srv_rerror_rate', 'same_srv_rate', 'diff_srv_rate',
        'srv_diff_host_rate', 'dst_host_count', 'dst_host_srv_count',
        'dst_host_same_srv_rate', 'dst_host_diff_srv_rate', 'dst_host_same_src_port_rate',
        'dst_host_srv_diff_host_rate', 'dst_host_serror_rate', 'dst_host_srv_serror_rate',
        'dst_host_rerror_rate', 'dst_host_srv_rerror_rate', 'label', 'difficulty'
    ]
    
    print("🔄 Loading NSL-KDD dataset...")
    
    try:
        # Load training data
        train_df = pd.read_csv('KDDTrain+.txt', names=column_names)
        test_df = pd.read_csv('KDDTest+.txt', names=column_names)
        
        # Remove difficulty column (not a feature)
        train_df = train_df.drop('difficulty', axis=1)
        test_df = test_df.drop('difficulty', axis=1)
        
        print(f"✅ Loaded {len(train_df)} training samples, {len(test_df)} test samples")
        
        # Prepare labels (normal vs attack)
        # NSL-KDD has specific attack types, we'll group them
        attack_types = {
            'normal': 'normal',
            'neptune': 'DoS', 'smurf': 'DoS', 'back': 'DoS', 'teardrop': 'DoS', 'pod': 'DoS', 'land': 'DoS',
            'ipsweep': 'Probe', 'portsweep': 'Probe', 'nmap': 'Probe', 'satan': 'Probe',
            'guess_passwd': 'R2L', 'ftp_write': 'R2L', 'imit': 'R2L', 'phf': 'R2L', 'multihop': 'R2L', 'warezmaster': 'R2L', 'warezclient': 'R2L', 'spy': 'R2L',
            'rootkit': 'U2R', 'buffer_overflow': 'U2R', 'loadmodule': 'U2R', 'perl': 'U2R', 'httptunnel': 'U2R', 'ps': 'U2R', 'sqlattack': 'U2R', 'xterm': 'U2R', 'named': 'U2R', 'sendmail': 'U2R', 'snmpgetattack': 'U2R', 'snmpguess': 'U2R', 'worm': 'U2R', 'xlock': 'U2R', 'xsnoop': 'U2R'
        }
        
        # Simplify: binary classification (normal vs attack)
        train_df['is_attack'] = (train_df['label'] != 'normal').astype(int)
        test_df['is_attack'] = (test_df['label'] != 'normal').astype(int)
        
        # Encode categorical variables
        categorical_cols = ['protocol_type', 'service', 'flag']
        encoders = {}
        
        for col in categorical_cols:
            le = LabelEncoder()
            train_df[col] = le.fit_transform(train_df[col])
            test_df[col] = le.transform(test_df[col])  # Use same encoding for test
            encoders[col] = le
        
        # Select features (exclude label columns)
        feature_cols = [col for col in train_df.columns if col not in ['label', 'is_attack']]
        X_train = train_df[feature_cols]
        y_train = train_df['is_attack']
        X_test = test_df[feature_cols]
        y_test = test_df['is_attack']
        
        print(f"🎯 Features selected: {len(feature_cols)}")
        print(f"📊 Training distribution: {y_train.value_counts().to_dict()}")
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train models
        
        # 1. Isolation Forest (for anomaly detection - unsupervised)
        print("\n🤖 Training Isolation Forest...")
        iso_model = IsolationForest(
            contamination=0.2,  # Approximate attack ratio
            random_state=42,
            n_estimators=150,
            max_samples='auto'
        )
        iso_model.fit(X_train_scaled[y_train == 0])  # Train only on normal traffic
        
        # 2. Random Forest (for classification - supervised, better metrics)
        print("🤖 Training Random Forest Classifier...")
        rf_model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            random_state=42,
            n_jobs=-1
        )
        rf_model.fit(X_train_scaled, y_train)
        
        # Evaluate Random Forest (better for metrics)
        y_pred = rf_model.predict(X_test_scaled)
        
        # Calculate metrics
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        
        print("\n" + "="*60)
        print("📊 MODEL PERFORMANCE METRICS")
        print("="*60)
        print(f"✅ Accuracy:  {accuracy:.4f} ({accuracy*100:.2f}%)")
        print(f"✅ Precision: {precision:.4f} ({precision*100:.2f}%)")
        print(f"✅ Recall:    {recall:.4f} ({recall*100:.2f}%)")
        print(f"✅ F1-Score:  {f1:.4f} ({f1*100:.2f}%)")
        print("="*60)
        
        # Detailed classification report
        print("\nDetailed Report:")
        print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))
        
        # Save models and preprocessing objects
        model_package = {
            'isolation_forest': iso_model,
            'random_forest': rf_model,
            'scaler': scaler,
            'encoders': encoders,
            'feature_cols': feature_cols,
            'metrics': {
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1': f1
            }
        }
        
        with open('trained_model.pkl', 'wb') as f:
            pickle.dump(model_package, f)
        
        print("\n💾 Model saved to 'trained_model.pkl'")
        print("🎉 Training complete! Ready for detection.")
        
        return model_package
        
    except FileNotFoundError:
        print("❌ Error: Dataset files not found!")
        print("📥 Please download NSL-KDD from:")
        print("   https://www.kaggle.com/datasets/hassan06/nslkdd")
        print("   Place KDDTrain+.txt and KDDTest+.txt in backend/ folder")
        return None

if __name__ == '__main__':
    train_nsl_kdd_model()