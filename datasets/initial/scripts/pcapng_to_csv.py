import os
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

def extract_pcapng_to_csv(pcapng_file_path, output_csv_path):
    filename = os.path.basename(pcapng_file_path).lower()
    print(f"Processing: {filename}...")

    try:
        packets = rdpcap(pcapng_file_path)
    except Exception as e:
        print(f"    Error reading file: {e}")
        return

    if len(packets) == 0:
        print("    No packets found.")
        return


    traffic_classes_map = {
        "bulk": "Bulk Data Transfer",
        "gaming": "Gaming",
        "interactive": "Interactive",
        "control": "Network Control",
        "voip": "VoIP",
        "web": "Web Browsing",
        "streaming": "Streaming",
        "background": "Background Telemetry"
    }


    drop_ports = [
        5353, 1900, 5355,           # Discovery (mDNS, SSDP, LLMNR)
        137, 138, 139, 445,         # NetBIOS / SMB
        123,                        # NTP (Clock Sync)
        67, 68                      # DHCP
    ]
    
    control_ports = [53]            # DNS

    # Ginawa nating None muna para ma-detect kung may match o wala
    default_traffic_class = None
    for key, value in traffic_classes_map.items():
        if key in filename:
            default_traffic_class = value
            break

    
    if default_traffic_class is None:
        print(f"    Skipping: Filename '{filename}' does not match any known traffic class (Dropped).")
        return

    packet_data = []
    
    for packet in packets:
        try:
            p_layer = None
            if packet.haslayer(IP): 
                p_layer = packet[IP]
            elif packet.haslayer(IPv6): 
                p_layer = packet[IPv6]

            if p_layer is None:
                continue 

            src_ip = p_layer.src
            dst_ip = p_layer.dst
            timestamp = float(packet.time)
            length = len(packet)

            src_port, dst_port, proto = 0, 0, "Unknown"
            if packet.haslayer(TCP):
                src_port, dst_port, proto = packet[TCP].sport, packet[TCP].dport, "6"
            elif packet.haslayer(UDP):
                src_port, dst_port, proto = packet[UDP].sport, packet[UDP].dport, "17"

            
            if src_port in drop_ports or dst_port in drop_ports:
                continue
            
            
            current_packet_class = default_traffic_class
            if src_port in control_ports or dst_port in control_ports:
                current_packet_class = traffic_classes_map["control"]

            
            ips = sorted([src_ip, dst_ip])
            ports = sorted([src_port, dst_port])
            biflow_id = f"{ips[0]}_{ips[1]}_{ports[0]}_{ports[1]}_{proto}"

            packet_data.append({
                "Timestamp": timestamp,
                "Biflow_ID": biflow_id,
                "Traffic_Class": current_packet_class, 
                "Source IP": src_ip,
                "Destination IP": dst_ip,
                "Source Port": src_port,
                "Destination Port": dst_port,
                "Protocol": proto,
                "Length": length
            })
        except Exception:
            continue 

    if not packet_data:
        print(f"    No relevant packets left after filtering.")
        return

    df = pd.DataFrame(packet_data)
    df = df.sort_values(by=["Biflow_ID", "Timestamp"])
    df.to_csv(output_csv_path, index=False)
    
    print(f"    Success: Extracted {len(packet_data)} valid packets.")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))

    captures_folder = os.path.join(project_root, "captures")
    output_folder = os.path.join(project_root, "parsed_packets")

    os.makedirs(output_folder, exist_ok=True)

    print("PCAPNG to CSV Conversion (Strict Filtering)")

    files_processed = 0

    for root, dirs, files in os.walk(captures_folder):
        for file in files:
            if file.lower().endswith((".pcap", ".pcapng")):
                pcapng_path = os.path.join(root, file)
                csv_name = os.path.splitext(file)[0] + ".csv"
                output_csv = os.path.join(output_folder, csv_name)

                extract_pcapng_to_csv(pcapng_path, output_csv)
                files_processed += 1

    print(f"Finished! Processed {files_processed} files.")