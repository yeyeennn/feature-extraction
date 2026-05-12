
import pandas as pd
import numpy as np 
import os
from pathlib import Path

# Config
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent 
INPUT_DIR = PROJECT_ROOT / "parsed_packets" 
OUTPUT_DIR = PROJECT_ROOT / "flow_features"

os.makedirs(OUTPUT_DIR, exist_ok=True)


TRAFFIC_CLASSES_MAP = {
    "bulk": "Bulk Data Transfer",
    "gaming": "Gaming",
    "interactive": "Interactive",
    "control": "Network Control",
    "voip": "VoIP",
    "web": "Web Browsing",
    "streaming": "Streaming"
}

def process_csv_by_flow(file_path: Path):
    filename = file_path.name.lower()
    print(f"Grouping flows from {file_path.name}...")
    
    if not file_path.exists():
        return []

    df = pd.read_csv(file_path)
    if df.empty:
        return []

    # Tukuyin ang label base sa filename para sa dataset
    assigned_label = "Other/Media"
    for key, value in TRAFFIC_CLASSES_MAP.items():
        if key in filename:
            assigned_label = value
            break

  
    flow_groups = df.groupby('Biflow_ID')
    
    extracted_flows = []

    for biflow_id, group in flow_groups:
       
        if len(group) < 3:
            continue

        timestamps = group['Timestamp'].values
        sizes = group['Length'].values
        
     
        iat = np.diff(timestamps) if len(timestamps) > 1 else [0]
        
        duration = float(timestamps[-1] - timestamps[0])
        
       
        row = {
            "Biflow_ID": biflow_id,
            "mean_packet_size": float(np.mean(sizes)),
            "std_packet_size": float(np.std(sizes)),
            "min_packet_size": float(np.min(sizes)),
            "max_packet_size": float(np.max(sizes)),
            "total_bytes": int(np.sum(sizes)),
            "packet_count": len(group),
            "duration": duration,
            "mean_iat": float(np.mean(iat)),
            "std_iat": float(np.std(iat)),
            "max_iat": float(np.max(iat)),
            "min_iat": float(np.min(iat)),
       
            "byte_rate": float(np.sum(sizes) / (duration + 1e-6)),
    
            "packet_rate": float(len(group) / (duration + 1e-6)),
            "label": assigned_label
        }
        extracted_flows.append(row)
        
    return extracted_flows

if __name__ == "__main__":
    all_flow_data = []

    for file in os.listdir(INPUT_DIR):
        if file.endswith(".csv"):
            csv_path = INPUT_DIR / file
            flows = process_csv_by_flow(csv_path)
            all_flow_data.extend(flows)
    
    if all_flow_data:
        final_df = pd.DataFrame(all_flow_data)
      
        final_output = OUTPUT_DIR / "final_flow_dataset.csv"
        final_df.to_csv(final_output, index=False)
        
     
        print(f"Total Unique Flows Extracted: {len(final_df)}")
        print("\nDistribution per Class:")
        print(final_df['label'].value_counts())