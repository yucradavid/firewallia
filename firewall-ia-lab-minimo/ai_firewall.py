import argparse
import subprocess
import time
import os
import logging
import joblib
import pandas as pd

from scapy.all import rdpcap, IP, TCP, UDP

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

WHITELIST = {
    "127.0.0.1",
    "10.10.10.1",
    "192.168.10.1",
    "192.168.10.10",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

log = logging.getLogger("ai_firewall")

def empty_flow():
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
    }

def extract_live_features(pcap_file, window_size=0.05):
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
            flows[key] = empty_flow()

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

    ips = []
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

        ips.append(src)
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
        })

    return ips, pd.DataFrame(rows)

def block_ip(ip):
    if ip in WHITELIST:
        log.info(f"WHITELIST: no se bloquea {ip}")
        return

    cmd = [
        "nft",
        "add",
        "element",
        "inet",
        "filter",
        "ia_blocklist",
        f"{{ {ip} timeout 1h }}",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode == 0:
        log.warning(f"BLOQUEADO por IA: {ip}")
    elif "File exists" in result.stderr:
        log.info(f"IP ya estaba bloqueada: {ip}")
    else:
        log.error(f"No se pudo bloquear {ip}: {result.stderr.strip()}")

def capture_window(interface, output, seconds):
    if os.path.exists(output):
        os.remove(output)

    cmd = [
        "timeout",
        str(seconds),
        "tcpdump",
        "-i",
        interface,
        "-nn",
        "-w",
        output,
        "-U",
    ]

    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", required=True, help="Interfaz de captura. Ejemplo: enp0s8")
    parser.add_argument("--window", type=int, default=10, help="Segundos por ventana")
    parser.add_argument("--model", default="/opt/ai_firewall/models/firewall_ai_model.joblib")
    parser.add_argument("--scaler", default="/opt/ai_firewall/models/scaler.joblib")
    parser.add_argument("--pcap", default="/tmp/ai_firewall_live.pcap")

    args = parser.parse_args()

    clf = joblib.load(args.model)
    scaler = joblib.load(args.scaler)

    log.info("Motor IA iniciado")
    log.info(f"Interfaz de captura: {args.iface}")

    while True:
        capture_window(args.iface, args.pcap, args.window)

        try:
            ips, df = extract_live_features(args.pcap)

            if df.empty:
                log.info("Sin tráfico en esta ventana")
                continue

            X_sc = scaler.transform(df[FEATURES].values)
            preds = clf.predict(X_sc)
            probas = clf.predict_proba(X_sc)

            for ip, pred, proba, row in zip(ips, preds, probas, df.to_dict(orient="records")):
                conf = max(proba) * 100

                log.info(f"IP={ip} pred={pred} conf={conf:.2f}%")

                if pred == "attack":
                    block_ip(ip)

        except Exception as e:
            log.error(f"Error procesando ventana: {e}")

        time.sleep(1)

if __name__ == "__main__":
    main()
