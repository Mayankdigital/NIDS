import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.decomposition import PCA
from sklearn.preprocessing import StandardScaler
from pathlib import Path

# Setup paths
BASE_DIR = Path(__file__).parent.parent / "nids_dataset" / "final"
# Using balanced CSV to avoid memory issues and ensure attacks aren't drowned out by benign traffic
CSV_PATH = BASE_DIR / "nids_dataset_balanced.csv" 
OUT_DIR = BASE_DIR / "ml_results"
OUT_DIR.mkdir(parents=True, exist_ok=True)

def main():
    print(f"Loading data from {CSV_PATH}...")
    df = pd.read_csv(CSV_PATH)
    
    if "label" not in df.columns:
        print("Error: 'label' column not found in dataset.")
        return

    print("Separating features and labels...")
    drop_cols = [
        "label", "class_name", "experiment_id", "src_ip", "dst_ip", 
        "timestamp", "split", "src_port", "dst_port", "protocol"
    ]
    cols_to_drop = [c for c in drop_cols if c in df.columns]
    
    y_raw = df["label"].values
    is_attack = (y_raw > 0)
    
    X = df.drop(columns=cols_to_drop).select_dtypes(include=[np.number])
    X = X.replace([np.inf, -np.inf], np.nan).fillna(0)

    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print("Applying PCA (2 components)...")
    pca = PCA(n_components=2)
    X_pca = pca.fit_transform(X_scaled)

    print(f"Explained variance ratio: {pca.explained_variance_ratio_}")

    print("Generating PCA Plot...")
    
    # Set up matplotlib figure to closely match the requested style
    plt.figure(figsize=(7, 6))
    
    # Ensure Normal traffic is plotted first (underneath), then Attacks on top
    
    # 1. Plot Normal Traffic (Blue tri_right marker)
    plt.scatter(
        X_pca[~is_attack, 0], X_pca[~is_attack, 1],
        c='#3b82f6',        # Blue
        marker=4,           # tri_right marker (looks like the blue marker in image)
        s=10,               # size
        alpha=0.5,
        label='Normal'
    )
    
    # 2. Plot Attack Traffic (Red tri_down/Y marker)
    plt.scatter(
        X_pca[is_attack, 0], X_pca[is_attack, 1],
        c='#e11d48',        # Red
        marker='1',         # tri_down marker (looks similar to the red 'Y' marker)
        s=10,
        alpha=0.5,
        label='Attacks'
    )

    plt.xlabel('Component 1', fontsize=12)
    plt.ylabel('Component 2', fontsize=12)
    
    # Create legend with larger markers for visibility
    legend = plt.legend(loc='upper right', fontsize=11, markerscale=3)
    
    plt.grid(False) # The reference image has no grid
    
    # Save the plot
    out_path = OUT_DIR / "pca_plot_comparison.png"
    plt.savefig(out_path, dpi=300, bbox_inches='tight')
    print(f"\n✅ PCA plot saved successfully to: {out_path}")
    plt.close()

if __name__ == "__main__":
    main()
