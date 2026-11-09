import pandas as pd

print("Loading benign.csv...")
df = pd.read_csv("nids_dataset/processed/benign.csv", low_memory=False)
initial_len = len(df)

print(f"Initial rows: {initial_len}")
df = df[df['experiment_id'] != 'BENIGN_DIVERSE']
final_len = len(df)

print(f"Removed {initial_len - final_len} rows.")
print(f"Saving {final_len} rows...")
df.to_csv("nids_dataset/processed/benign.csv", index=False)
print("Done!")
