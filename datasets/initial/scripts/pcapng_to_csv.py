import os
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

def extract_pcapng_to_csv(pcapng_file_path, output_csv_path):
    print(f"Processing: {os.path.basename(pcapng_file_path)}...")

    try:
        packets = rdpcap(pcapng_file_path)
    except Exception as e:
        print(f"   Error reading file: {e}")
        return

    if len(packets) == 0:
        print("   No packets found.")
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

   
            src_port, dst_port, proto = 0, 0, None
            if packet.haslayer(TCP):
                src_port, dst_port, proto = packet[TCP].sport, packet[TCP].dport, "TCP"
            elif packet.haslayer(UDP):
                src_port, dst_port, proto = packet[UDP].sport, packet[UDP].dport, "UDP"
            

            if proto is None:
                continue

            ips = sorted([src_ip, dst_ip])
            ports = sorted([src_port, dst_port])
            biflow_id = f"{ips[0]}_{ips[1]}_{ports[0]}_{ports[1]}_{proto}"

            packet_data.append({
                "Timestamp": timestamp,
                "Biflow_ID": biflow_id,
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
        print(f"  No valid IP flows found after filtering.")
        return

    df = pd.DataFrame(packet_data)
    
    df = df.sort_values(by=["Biflow_ID", "Timestamp"])
    
    num_flows = df['Biflow_ID'].nunique()
    print(f"   Success: Extracted {len(packet_data)} packets across {num_flows} unique flows!\n")
    
    df.to_csv(output_csv_path, index=False)
    print(f"   Success: Extracted {len(packet_data)} valid flow packets!\n")

if __name__ == "__main__":
    
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))

    captures_folder = os.path.join(project_root, "captures")
    output_folder = os.path.join(project_root, "parsed_packets")

    print(f"PCAPNG to High-Integrity CSV Converter")
    
    if not os.path.exists(captures_folder):
        print(f"ERROR: Folder not found: {captures_folder}")
    else:
        os.makedirs(output_folder, exist_ok=True)
        
        found_files = 0
        for root, dirs, files in os.walk(captures_folder):
            for file in files:
                if file.lower().endswith((".pcap", ".pcapng")):
                    found_files += 1
                    pcapng_path = os.path.join(root, file)
                    csv_name = os.path.splitext(file)[0] + ".csv"
                    output_csv = os.path.join(output_folder, csv_name)
                    extract_pcapng_to_csv(pcapng_path, output_csv)
        
        if found_files == 0:
            print("No .pcap or .pcapng files found.")
        else:
            print(f"Task finished. Processed {found_files} files.")