"""
Diagnostic script to check what's in the model.pkl file
"""

import joblib
import pickle
import os

def check_model_file():
    model_path = 'models/model.pkl'
    
    if not os.path.exists(model_path):
        print(f"✗ Model file not found: {model_path}")
        return
    
    print("="*60)
    print("Model File Diagnostics")
    print("="*60)
    
    # Check file size
    file_size = os.path.getsize(model_path)
    print(f"\nFile: {model_path}")
    print(f"Size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
    
    # Try loading with joblib
    print("\n" + "-"*60)
    print("Attempting to load with joblib...")
    try:
        obj = joblib.load(model_path)
        print(f"✓ Loaded successfully with joblib")
        print(f"  Type: {type(obj)}")
        print(f"  Type name: {type(obj).__name__}")
        
        if hasattr(obj, '__class__'):
            print(f"  Class: {obj.__class__}")
        
        # Check if it's a classifier
        if hasattr(obj, 'predict'):
            print(f"  ✓ Has predict method")
            print(f"  ✓ Has predict_proba: {hasattr(obj, 'predict_proba')}")
            
            if hasattr(obj, 'classes_'):
                print(f"  ✓ Classes: {obj.classes_}")
            
            if hasattr(obj, 'n_estimators'):
                print(f"  ✓ Number of trees: {obj.n_estimators}")
        else:
            print(f"  ✗ No predict method found!")
            print(f"  Available attributes: {dir(obj)[:10]}...")
            
            # If it's a numpy array, show shape
            if hasattr(obj, 'shape'):
                print(f"  ✗ This is a numpy array with shape: {obj.shape}")
                print(f"  ✗ This is NOT a valid classifier!")
                print(f"\n  The model.pkl file is corrupted or incorrect.")
                print(f"  Please retrain by running: python retrain_classifier.py")
        
    except Exception as e:
        print(f"✗ Failed with joblib: {e}")
        
        # Try with pickle
        print("\nAttempting to load with pickle...")
        try:
            with open(model_path, 'rb') as f:
                obj = pickle.load(f)
            print(f"✓ Loaded with pickle")
            print(f"  Type: {type(obj)}")
        except Exception as e2:
            print(f"✗ Failed with pickle too: {e2}")
    
    # Check backup if exists
    backup_path = 'models/model.pkl.backup'
    if os.path.exists(backup_path):
        print("\n" + "-"*60)
        print(f"Found backup: {backup_path}")
        print("You can restore it with:")
        print("  import shutil")
        print(f"  shutil.copy('{backup_path}', '{model_path}')")

if __name__ == "__main__":
    check_model_file()