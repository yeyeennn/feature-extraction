import os
import pandas as pd
from scapy.all import rdpcap, IP, IPv6, TCP, UDP


def extract_pcapng_to_csv(pcapng_file_path, output_csv_path):
    print(f"Processing: {os.path.basename(pcapng_file_path)}...")

    try:
        packets = rdpcap(pcapng_file_path)
    except Exception as e:
        print(f"  [!] Error reading file: {e}")
        return

    if len(packets) == 0:
        print("  [!] No packets found.")
        return

    packet_data = []
    
    for packet in packets:
        try:
            
            # This bypasses the strict .haslayer(IP) check
            p_layer = None
            if packet.haslayer('IP'): p_layer = packet['IP']
            elif packet.haslayer('IPv6'): p_layer = packet['IPv6']
            
            # If standard IP layers fail, we look for the payload of the Ethernet frame
            if p_layer is None and packet.payload:
                p_layer = packet.payload

            if p_layer:
                # Use getattr to avoid crashes if src/dst aren't named exactly right
                src_ip = getattr(p_layer, 'src', '0.0.0.0')
                dst_ip = getattr(p_layer, 'dst', '0.0.0.0')
                
                # Check for Transport Layer
                src_port, dst_port, proto = 0, 0, "OTHER"
                if packet.haslayer(TCP):
                    src_port, dst_port, proto = packet[TCP].sport, packet[TCP].dport, "TCP"
                elif packet.haslayer(UDP):
                    src_port, dst_port, proto = packet[UDP].sport, packet[UDP].dport, "UDP"

                packet_data.append({
                    "Timestamp": float(packet.time),
                    "Source IP": src_ip,
                    "Destination IP": dst_ip,
                    "Source Port": src_port,
                    "Destination Port": dst_port,
                    "Protocol": proto,
                    "Length": len(packet)
                })
        except:
            continue # Skip malformed packets

    if not packet_data:
        print(f"  [!] Still no IP data found. We might need to check the DLT (Link Type).")
        return

    df = pd.DataFrame(packet_data)
    df.to_csv(output_csv_path, index=False)
    print(f"  Success: Extracted {len(packet_data)} packets!\n")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))

    captures_folder = os.path.join(project_root, "captures")
    output_folder = os.path.join(project_root, "parsed_packets")

    print(f"--- PCAPNG to CSV Converter ---")
    
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