from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import sys

FEATURES = [
    "total_pkts",
    "tcp_pkts",
    "udp_pkts",
    "other_pkts",
    "unique_dports_count",
    "syn_ratio",
    "avg_pkt_size",
    "duration_sec",
    "bytes_per_sec",
    "port_scan_score",
    "small_syn_score",
    "potential_flood",
    "potential_scan",
]

def empty_flow(label):
    return {
        "total_pkts": 0,
        "tcp_pkts": 0,
        "udp_pkts": 0,
        "other_pkts": 0,
        "unique_dports": set(),
        "syn_count": 0,
        "total_bytes": 0,
        "first_ts": None,
        "last_ts": None,
        "label": label,
    }

def extract_features(pcap_file, label, window_size=0.05):
    packets = rdpcap(pcap_file)
    flows = {}

    for pkt in packets:
        if IP not in pkt:
            continue

        src = pkt[IP].src
        ts = float(pkt.time)
        window_id = int(ts / window_size)
        key = (src, window_id)

        if key not in flows:
            flows[key] = empty_flow(label)

        f = flows[key]
        f["total_pkts"] += 1
        f["total_bytes"] += len(pkt)

        if f["first_ts"] is None:
            f["first_ts"] = ts
        f["last_ts"] = ts

        if TCP in pkt:
            f["tcp_pkts"] += 1
            f["unique_dports"].add(int(pkt[TCP].dport))

            flags = int(pkt[TCP].flags)
            syn = bool(flags & 0x02)
            ack = bool(flags & 0x10)

            if syn and not ack:
                f["syn_count"] += 1

        elif UDP in pkt:
            f["udp_pkts"] += 1
            f["unique_dports"].add(int(pkt[UDP].dport))
        else:
            f["other_pkts"] += 1

    rows = []

    for (src, window_id), f in flows.items():
        total = f["total_pkts"]
        tcp = f["tcp_pkts"]
        unique_ports = len(f["unique_dports"])

        duration = 1.0
        if f["first_ts"] is not None and f["last_ts"] is not None:
            duration = max(f["last_ts"] - f["first_ts"], 0.05)

        syn_ratio = f["syn_count"] / tcp if tcp > 0 else 0
        avg_pkt_size = f["total_bytes"] / total if total > 0 else 0
        bytes_per_sec = f["total_bytes"] / duration if duration > 0 else 0
        port_scan_score = unique_ports / total if total > 0 else 0
        small_syn_score = (syn_ratio / max(avg_pkt_size, 1)) * 10000

        potential_flood = 1 if syn_ratio > 0.5 and total > 5 else 0
        potential_scan = 1 if unique_ports > 10 else 0

        rows.append({
            "total_pkts": total,
            "tcp_pkts": tcp,
            "udp_pkts": f["udp_pkts"],
            "other_pkts": f["other_pkts"],
            "unique_dports_count": unique_ports,
            "syn_ratio": syn_ratio,
            "avg_pkt_size": avg_pkt_size,
            "duration_sec": duration,
            "bytes_per_sec": bytes_per_sec,
            "port_scan_score": port_scan_score,
            "small_syn_score": small_syn_score,
            "potential_flood": potential_flood,
            "potential_scan": potential_scan,
            "label": f["label"],
        })

    return pd.DataFrame(rows)

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Uso: python3 extract_features.py <pcap> <normal|attack> <salida.csv>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    label = sys.argv[2]
    output = sys.argv[3]

    df = extract_features(pcap_file, label)
    df.to_csv(output, index=False)

    print(f"[OK] Archivo generado: {output}")
    print(df.head())
    print(df.shape)
    print(df["label"].value_counts())
