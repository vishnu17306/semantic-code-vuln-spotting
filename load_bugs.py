from datasets import load_dataset

ds = load_dataset("AliArshad/Bugzilla_Eclipse_Bug_Reports_Dataset")
print(ds)

split_name = list(ds.keys())[0]
df = ds[split_name].to_pandas()

print(f"\nSplit: {split_name}, rows: {len(df)}")
print("\nColumns:", df.columns.tolist())

print("\nFirst 3 rows:")
print(df.head(3).to_string())

# Show the value counts for any column with few distinct values
# (a severity or label column would show up here)
for col in df.columns:
    if df[col].nunique() <= 15:
        print(f"\n--- {col} ---")
        print(df[col].value_counts())
from datasets import load_dataset

ds = load_dataset("AliArshad/Bugzilla_Eclipse_Bug_Reports_Dataset")
print(ds)

split_name = list(ds.keys())[0]
df = ds[split_name].to_pandas()

print(f"\nSplit: {split_name}, rows: {len(df)}")
print("\nColumns:", df.columns.tolist())

print("\nFirst 3 rows:")
print(df.head(3).to_string())

# Show the value counts for any column with few distinct values
# (a severity or label column would show up here)
for col in df.columns:
    if df[col].nunique() <= 15:
        print(f"\n--- {col} ---")
        print(df[col].value_counts())