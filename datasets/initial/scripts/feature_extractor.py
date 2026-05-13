import pandas as pd
import numpy as np
import os
from pathlib import Path


# ==========================================
# PATHS
# ==========================================
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent.parent

INPUT_DIR = PROJECT_ROOT / "parsed_packets"
OUTPUT_DIR = PROJECT_ROOT / "flow_features"

os.makedirs(OUTPUT_DIR, exist_ok=True)


# ==========================================
# SETTINGS
# ==========================================
N_PACKETS = 5      # Change to 3, 5, 10, etc.


# ==========================================
# CLASS MAPPING
# ==========================================
TRAFFIC_CLASSES_MAP = {
    "bulk": "Bulk Data Transfer",
    "gaming": "Gaming",
    "interactive": "Interactive",
    "control": "Network Control",
    "voip": "VoIP",
    "web": "Web Browsing",
    "streaming": "Streaming",
    "background": "Background"
}


# ==========================================
# GET LABEL FROM FILE NAME
# Unknown labels are dropped
# ==========================================
def get_label_from_filename(filename):

    filename = filename.lower()

    for key, label in TRAFFIC_CLASSES_MAP.items():
        if key in filename:
            return label

    return None


# ==========================================
# EXTRACT FLOW FEATURES
# ==========================================
def process_csv_by_flow(file_path: Path):

    filename = file_path.name.lower()

    print(f"Processing: {file_path.name}")

    if not file_path.exists():
        return []

    df = pd.read_csv(file_path)

    if df.empty:
        print("   Empty CSV. Skipping.")
        return []

    assigned_label = get_label_from_filename(filename)

    # Drop unknown labels
    if assigned_label is None:
        print(f"   Unknown traffic class. Dropped.")
        return []

    flow_groups = df.groupby("Biflow_ID")

    extracted_flows = []

    for biflow_id, group in flow_groups:

        # chronological order
        group = group.sort_values("Timestamp")

        # ONLY FIRST N PACKETS
        group = group.head(N_PACKETS)

        # Skip tiny flows
        if len(group) < 3:
            continue

        timestamps = group["Timestamp"].values
        sizes = group["Length"].values

        # Inter-arrival time
        iat = np.diff(timestamps)

        duration = float(timestamps[-1] - timestamps[0])

        row = {
            "Biflow_ID": biflow_id,

            # packet statistics
            "mean_packet_size": float(np.mean(sizes)),
            "std_packet_size": float(np.std(sizes)),
            "min_packet_size": float(np.min(sizes)),
            "max_packet_size": float(np.max(sizes)),

            # flow statistics
            "total_bytes": int(np.sum(sizes)),
            "packet_count": len(group),
            "duration": duration,

            # timing statistics
            "mean_iat": float(np.mean(iat)),
            "std_iat": float(np.std(iat)),
            "min_iat": float(np.min(iat)),
            "max_iat": float(np.max(iat)),

            # rates
            "byte_rate": float(
                np.sum(sizes) / (duration + 1e-6)
            ),

            "packet_rate": float(
                len(group) / (duration + 1e-6)
            ),

            # class label
            "label": assigned_label
        }

        extracted_flows.append(row)

    print(
        f"   Extracted {len(extracted_flows)} flows "
        f"({assigned_label})"
    )

    return extracted_flows


# ==========================================
# MAIN
# ==========================================
if __name__ == "__main__":

    print(
        f"\nFlow Feature Extraction "
        f"(First {N_PACKETS} Packets)\n"
    )

    class_data = {}

    for file in os.listdir(INPUT_DIR):

        if not file.endswith(".csv"):
            continue

        csv_path = INPUT_DIR / file

        flows = process_csv_by_flow(csv_path)

        if not flows:
            continue

        class_name = flows[0]["label"]

        if class_name not in class_data:
            class_data[class_name] = []

        class_data[class_name].extend(flows)

    print("\nSaving class datasets...\n")

    for class_name, flows in class_data.items():

        df = pd.DataFrame(flows)

        safe_name = (
            class_name.lower()
            .replace(" ", "_")
        )

        output_file = (
            OUTPUT_DIR /
            f"{safe_name}.csv"
        )

        df.to_csv(
            output_file,
            index=False
        )

        print(
            f"{class_name}: "
            f"{len(df)} flows"
        )

        print(
            f"Saved -> {output_file}"
        )

    print("\nFeature extraction complete.")