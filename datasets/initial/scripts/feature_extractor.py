import pandas as pd
import numpy as np 
import os
from typing import Dict
from pathlib import Path

#config
WINDOW_SIZE = 100 
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent 
# pa csv folder
INPUT_DIR = PROJECT_ROOT / "parsed_packets" 
OUTPUT_DIR = PROJECT_ROOT / "flow_features"

os.makedirs(OUTPUT_DIR, exist_ok=True)

FILE_CONFIG = [
    { "file": "network_control_and_signaling.csv", "label": "signaling", "group": 0 },
    { "file": "voip_call_NEW.csv", "label": "voip", "group": 0 },
    { "file": "video_call_with_mic_NEW.csv", "label": "video_call", "group": 0 },
    { "file": "VoIP_validation_set_MESSENGER.csv", "label": "voip", "group": 1 },
    { "file": "gaming_NEW.csv", "label": "gaming", "group": 0 },
    { "file": "interactive_NEW.csv", "label": "interactive", "group": 0 },
    { "file": "video_streaming_NEW.csv", "label": "video_streaming", "group": 0 },
    { "file": "web_browsing_NEW.csv", "label": "web_browsing", "group": 0 },
    { "file": "bulk_downloads_COMPLETE_NEW.csv", "label": "bulk_download", "group": 0 },
    { "file": "bulk_downloads_INCOMPLETE.csv", "label": "bulk_download", "group": 0 }
]

def calculate_advanced_features(iat: np.ndarray, sizes: np.ndarray) -> Dict[str, float]:
    if len(iat) == 0:
        return {k: 0.0 for k in ["burst_density", "mean_burst_time", "std_burst_time", "mean_idle_time", "std_idle_time", "idle_ratio"]}

    threshold = max(np.mean(iat) + 2 * np.std(iat), 0.05)
    idle_indices = np.where(iat > threshold)[0]
    
    if len(idle_indices) > 0:
        idle_times = iat[idle_indices]
        mean_idle, std_idle, total_idle_time = float(np.mean(idle_times)), float(np.std(idle_times)), np.sum(idle_times)
    else:
        mean_idle, std_idle, total_idle_time = 0.0, 0.0, 0.0

    total_time = np.sum(iat)
    total_active_time = total_time - total_idle_time
    burst_density = float(np.sum(sizes)) / (total_active_time + 1e-6)

    return {
        "burst_density": burst_density,
        "mean_burst_time": total_active_time / (len(idle_indices) + 1),
        "std_burst_time": 0.0,
        "mean_idle_time": mean_idle,
        "std_idle_time": std_idle, 
        "idle_ratio": total_idle_time / (total_time + 1e-6)
    }

def process_csv_to_features(file_path: Path, label: str, group_id: int):
    print(f"Extracting features from {file_path.name}...")
    if not file_path.exists():
        print(f"  Skipping: {file_path.name} not found.")
        return []

    # pag read ng csv files from previous file
    df = pd.read_csv(file_path)
    if df.empty:
        return []

    flow_data = []
    
    # Windowing loop
    for i in range(0, len(df), WINDOW_SIZE):
        window = df.iloc[i : i + WINDOW_SIZE]
        if len(window) < 10: continue
            
        timestamps = window['Timestamp'].values
        sizes = window['Length'].values
        iat = np.diff(timestamps)
        
        adv_stats = calculate_advanced_features(iat, sizes)
        
        row = {
            "mean_packet_size": float(np.mean(sizes)),
            "std_packet_size": float(np.std(sizes)),
            "min_packet_size": float(np.min(sizes)),
            "max_packet_size": float(np.max(sizes)),
            "total_bytes": int(np.sum(sizes)),
            "mean_iat": float(np.mean(iat)) if len(iat) > 0 else 0.0,
            "std_iat": float(np.std(iat)) if len(iat) > 0 else 0.0,
            "max_iat": float(np.max(iat)) if len(iat) > 0 else 0.0,
            "flow_duration": float(timestamps[-1] - timestamps[0]),
            "packet_count": len(window),
            "large_packet_ratio": float(np.sum(sizes > 1200) / len(sizes)),
            "burst_density": adv_stats["burst_density"],
            "mean_burst_time": adv_stats["mean_burst_time"],
            "label": label,
            "group_id": group_id
        }
        flow_data.append(row)
        
    print(f"  Created {len(flow_data)} windows.")
    return flow_data

if __name__ == "__main__":
    all_data = []
    for config in FILE_CONFIG:
        csv_path = INPUT_DIR / config["file"]
        rows = process_csv_to_features(csv_path, config["label"], config["group"])
        all_data.extend(rows)
    
    if all_data:
        final_df = pd.DataFrame(all_data)
        final_df.to_csv(OUTPUT_DIR / "final_dataset.csv", index=False)
        print(f"\n--- SUCCESS! Total Windows Extracted: {len(final_df)} ---")
        print(final_df['label'].value_counts())