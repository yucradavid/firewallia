# Firewall con IA - Laboratorio

Repositorio mínimo del laboratorio realizado en VirtualBox.

Arquitectura usada:

- VM1 FirewallIA: Ubuntu Server, nftables, IA, `10.10.10.1` y `192.168.10.1`.
- VM2 UbuntuAtacante: Ubuntu Server, `10.10.10.20`.
- VM3 ServidorVictima: Ubuntu Server con Nginx/SSH, `192.168.10.10`.

## Estructura

```text
firewall-ia-lab/
├── nftables.conf
├── extract_features.py
├── train_model.py
├── ai_firewall.py
├── requirements.txt
├── data/
├── models/
├── systemd/
│   └── ai-firewall.service
└── informe/
```

Los archivos generados en la VM no se incluyen por defecto:

- `data/traffic-normal.pcap`
- `data/traffic-attack.pcap`
- `data/normal.csv`
- `data/attack.csv`
- `data/dataset.csv`
- `models/firewall_ai_model.joblib`
- `models/scaler.joblib`
- `models/metrics_comparison.csv`
- `models/feature_importance.csv`
- `informe/informe_final.pdf`

Estos se generan ejecutando los scripts dentro de la VM1 FirewallIA.
