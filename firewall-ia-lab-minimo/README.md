# Firewall con IA - Laboratorio en VirtualBox

Repositorio del laboratorio **Firewall con IA** desarrollado en un entorno controlado con tres máquinas virtuales en VirtualBox.

El proyecto implementa un firewall clásico con `nftables` y luego lo integra con un modelo de Inteligencia Artificial entrenado con tráfico normal y tráfico de ataque. La IA analiza capturas de red, clasifica el comportamiento como `normal` o `attack` y, si detecta ataque, bloquea automáticamente la IP origen usando el set dinámico `ia_blocklist` de `nftables`.

---

## 1. Objetivo del proyecto

El objetivo es demostrar un flujo completo de seguridad de red:

```text
Captura de tráfico → Extracción de características → Dataset etiquetado → Entrenamiento IA → Integración con nftables → Bloqueo automático
```

En otras palabras, el sistema no solo usa reglas estáticas de firewall, sino que también incorpora una capa de detección basada en IA para identificar tráfico sospechoso y bloquear automáticamente al atacante.

---

## 2. Arquitectura usada

El laboratorio se implementó con tres máquinas virtuales:

| Máquina | Rol | Sistema | IP principal | Función |
|---|---|---|---|---|
| VM1 | FirewallIA | Ubuntu Server | `10.10.10.1` y `192.168.10.1` | Firewall, captura de tráfico, IA y bloqueo |
| VM2 | UbuntuAtacante | Ubuntu Server | `10.10.10.20` | Genera tráfico normal y ataques controlados |
| VM3 | ServidorVictima | Ubuntu Server | `192.168.10.10` | Servidor protegido con Nginx y SSH |

La comunicación queda así:

```text
VM2 UbuntuAtacante        VM1 FirewallIA                    VM3 ServidorVictima
10.10.10.20        →      10.10.10.1 / 192.168.10.1   →     192.168.10.10
LAB_EXT                   Firewall + IA                     LAB_LAN
```

La VM1 actúa como router/firewall entre la red externa `LAB_EXT` y la red interna `LAB_LAN`.

---

## 3. Estructura del repositorio

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

---

## 4. Explicación de cada archivo y carpeta

### `nftables.conf`

Contiene las reglas principales del firewall.

Este archivo configura:

- Política restrictiva `policy drop`.
- Permiso para tráfico establecido o relacionado.
- Permiso controlado para ICMP, SSH, HTTP y HTTPS.
- Registro de paquetes descartados con el prefijo `NFT-DROP`.
- Set dinámico `ia_blocklist`, usado por la IA para bloquear IPs sospechosas.

El punto más importante es este set:

```nft
set ia_blocklist {
    type ipv4_addr
    flags timeout
    timeout 1h
    comment "Gestionado por ai_firewall.py"
}
```

Este set permite agregar IPs temporalmente al firewall. Por ejemplo, cuando la IA detecta que `10.10.10.20` es atacante, la agrega a `ia_blocklist` y el firewall la bloquea.

---

### `extract_features.py`

Script encargado de leer archivos `.pcap` capturados con `tcpdump` y convertirlos en datos tabulares `.csv`.

Este script extrae 13 características de tráfico:

1. `total_pkts`
2. `tcp_pkts`
3. `udp_pkts`
4. `other_pkts`
5. `unique_dports_count`
6. `syn_ratio`
7. `avg_pkt_size`
8. `duration_sec`
9. `bytes_per_sec`
10. `port_scan_score`
11. `small_syn_score`
12. `potential_flood`
13. `potential_scan`

Además, agrega la columna:

```text
label
```

La columna `label` puede tener dos valores:

```text
normal
attack
```

Ejemplo de uso:

```bash
python3 extract_features.py data/traffic-normal.pcap normal data/normal.csv
python3 extract_features.py data/traffic-attack.pcap attack data/attack.csv
```

Explicación para exposición:

> Este script transforma el tráfico capturado en un dataset que puede entender un modelo de Machine Learning. No se entrena directamente con paquetes crudos, sino con características numéricas que representan el comportamiento de la red.

---

### `train_model.py`

Script encargado de entrenar y evaluar los modelos de IA.

Este script usa el archivo:

```text
data/dataset.csv
```

Entrena y compara cuatro modelos:

- Random Forest
- Gradient Boosting
- Decision Tree
- Logistic Regression

El modelo principal seleccionado es **Random Forest**, porque ofrece buen rendimiento y permite analizar importancia de características.

Archivos generados por este script:

```text
models/firewall_ai_model.joblib
models/scaler.joblib
models/metrics_comparison.csv
models/feature_importance.csv
```

Ejemplo de uso:

```bash
python3 train_model.py
```

Métricas obtenidas en la práctica final:

| Modelo | Accuracy | Recall attack | ROC-AUC |
|---|---:|---:|---:|
| Random Forest | 0.9981 | 0.9971 | 0.9992 |
| Gradient Boosting | 0.9981 | 0.9971 | 0.9999 |
| Decision Tree | 0.9972 | 0.9956 | 0.9978 |
| Logistic Regression | 0.9792 | 0.9769 | 0.9983 |

Explicación para exposición:

> En esta etapa se entrenó el modelo con tráfico normal y tráfico de ataque. El modelo aprende patrones como escaneo de puertos, alta proporción de SYN y comportamiento de flood. Luego se guarda en formato `.joblib` para ser usado por el firewall inteligente.

---

### `ai_firewall.py`

Es el motor principal del firewall con IA.

Este script realiza el proceso automático:

```text
Captura tráfico en vivo → Extrae features → Usa el modelo entrenado → Predice normal/attack → Bloquea IP atacante
```

Cuando detecta una IP con tráfico de ataque, ejecuta un comando similar a:

```bash
nft add element inet filter ia_blocklist { 10.10.10.20 timeout 1h }
```

También tiene una lista blanca para evitar bloquear IPs importantes del laboratorio, como:

```text
10.10.10.1
192.168.10.1
192.168.10.10
127.0.0.1
```

Explicación para exposición:

> Este archivo representa la integración entre la IA y el firewall. El modelo no se queda solo como experimento, sino que toma una decisión real: si detecta ataque, modifica dinámicamente `nftables` y bloquea la IP atacante.

---

### `requirements.txt`

Lista las librerías necesarias para ejecutar el proyecto.

Contenido esperado:

```text
scapy
pandas
numpy
scikit-learn
joblib
matplotlib
```

Instalación:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Explicación para exposición:

> Este archivo permite instalar todas las dependencias del proyecto de forma ordenada dentro de un entorno virtual de Python.

---

### Carpeta `data/`

Carpeta donde se guardan las capturas y datasets.

Archivos generados durante la práctica:

```text
data/traffic-normal.pcap
data/traffic-attack.pcap
data/normal.csv
data/attack.csv
data/dataset.csv
```

Función de cada archivo:

| Archivo | Descripción |
|---|---|
| `traffic-normal.pcap` | Captura de tráfico normal: ping y HTTP hacia Nginx |
| `traffic-attack.pcap` | Captura de tráfico de ataque: nmap, hping3, SSH repetido y puerto bloqueado |
| `normal.csv` | Features extraídas del tráfico normal |
| `attack.csv` | Features extraídas del tráfico de ataque |
| `dataset.csv` | Dataset final unido y balanceado |

Resultado final obtenido:

```text
Dataset final: 3694 filas y 14 columnas
attack: 2311
normal: 1383
sin valores NaN
```

Explicación para exposición:

> Esta carpeta contiene la evidencia principal para el entrenamiento. Aquí se ve cómo se pasó de tráfico real capturado en la red a un dataset etiquetado para Machine Learning.

---

### Carpeta `models/`

Carpeta donde se guardan los modelos y resultados del entrenamiento.

Archivos generados:

```text
models/firewall_ai_model.joblib
models/scaler.joblib
models/metrics_comparison.csv
models/feature_importance.csv
```

Función de cada archivo:

| Archivo | Descripción |
|---|---|
| `firewall_ai_model.joblib` | Modelo Random Forest entrenado |
| `scaler.joblib` | Escalador usado para normalizar los datos |
| `metrics_comparison.csv` | Comparación de métricas entre modelos |
| `feature_importance.csv` | Importancia de cada característica en Random Forest |

Explicación para exposición:

> Aquí están los resultados del aprendizaje automático. El modelo entrenado se guarda para no entrenar cada vez, y luego es cargado directamente por `ai_firewall.py` para tomar decisiones en vivo.

---

### Carpeta `systemd/`

Contiene el archivo del servicio Linux para ejecutar el firewall con IA de forma automática.

Archivo:

```text
systemd/ai-firewall.service
```

Este servicio permite ejecutar el motor IA como proceso del sistema:

```bash
sudo systemctl start ai-firewall
sudo systemctl status ai-firewall
sudo journalctl -u ai-firewall -f
```

Explicación para exposición:

> Con `systemd`, el firewall con IA deja de ser un script manual y pasa a comportarse como un servicio del sistema operativo. Esto permite iniciarlo, detenerlo, reiniciarlo y revisar sus logs de forma profesional.

---

### Carpeta `informe/`

Carpeta destinada a guardar el informe final y capturas usadas como evidencia.

Ejemplos de archivos que pueden agregarse:

```text
informe/informe_final.pdf
informe/capturas/
informe/presentacion.pptx
```

Explicación para exposición:

> Esta carpeta se usa para organizar la documentación final del laboratorio, incluyendo capturas de pantalla, resultados y el informe entregable.

---

## 5. Flujo completo realizado

### Paso 1: Configuración de red

Se configuraron tres máquinas virtuales:

- VM1 como firewall/router.
- VM2 como atacante.
- VM3 como servidor víctima.

Se validó conectividad con:

```bash
ping -c 4 10.10.10.1
ping -c 4 192.168.10.10
curl http://192.168.10.10
```

---

### Paso 2: Firewall clásico con nftables

Se configuró `nftables` con política restrictiva:

```text
policy drop
```

Se permitió solo tráfico necesario:

- SSH: puerto 22
- HTTP: puerto 80
- HTTPS: puerto 443
- ICMP controlado

Se validó con:

```bash
sudo nmap -Pn -sS -p 1-1000 192.168.10.10
```

Resultado esperado:

```text
22/tcp open ssh
80/tcp open http
443/tcp closed https
997 filtered tcp ports
```

---

### Paso 3: Logs de paquetes bloqueados

Se probó acceso a un puerto no permitido:

```bash
nc -vz -w 3 192.168.10.10 9999
```

Y en VM1 se verificó:

```bash
sudo journalctl -k | grep NFT-DROP | tail -20
```

Esto demuestra que el firewall bloquea y registra paquetes descartados.

---

### Paso 4: Captura de tráfico normal

En VM1:

```bash
sudo tcpdump -i enp0s8 -nn -w data/traffic-normal.pcap
```

En VM2:

```bash
for i in {1..600}; do
  curl -s http://192.168.10.10 > /dev/null
  ping -c 1 -W 1 192.168.10.10 > /dev/null
  sleep 0.2
done
```

Resultado obtenido:

```text
7219 paquetes capturados
traffic-normal.pcap: 1.2 MB
```

---

### Paso 5: Captura de tráfico de ataque

En VM1:

```bash
sudo tcpdump -i enp0s8 -nn -w data/traffic-attack.pcap
```

En VM2 se ejecutaron ataques controlados:

```bash
sudo nmap -Pn -sS -p 1-1000 192.168.10.10
sudo hping3 -S -p 80 -c 4000 -i u10000 192.168.10.10
for i in {1..80}; do
  ssh -o BatchMode=yes -o ConnectTimeout=2 usuariofalso@192.168.10.10
done
nc -vz -w 3 192.168.10.10 9999
```

Resultado obtenido:

```text
15278 paquetes capturados
traffic-attack.pcap: 1.6 MB
```

---

### Paso 6: Generación del dataset

Se ejecutó:

```bash
python3 extract_features.py data/traffic-normal.pcap normal data/normal.csv
python3 extract_features.py data/traffic-attack.pcap attack data/attack.csv
```

Resultados:

```text
normal.csv: 1383 filas
attack.csv: 2311 filas
dataset.csv: 3694 filas y 14 columnas
```

Validación:

```text
13 features + label
sin valores NaN
balance aceptable entre normal y attack
```

---

### Paso 7: Entrenamiento del modelo

Se ejecutó:

```bash
python3 train_model.py
```

Se compararon cuatro modelos:

- Random Forest
- Gradient Boosting
- Decision Tree
- Logistic Regression

El modelo principal fue Random Forest.

Resultado final:

```text
accuracy: 0.9981
recall_attack: 0.9971
roc_auc: 0.9992
```

---

### Paso 8: Integración IA + nftables

Se copió el modelo final a `/opt/ai_firewall`:

```bash
sudo cp ai_firewall.py /opt/ai_firewall/
sudo cp models/firewall_ai_model.joblib /opt/ai_firewall/models/
sudo cp models/scaler.joblib /opt/ai_firewall/models/
```

El servicio `ai-firewall` analiza tráfico en ventanas de 10 segundos.

---

### Paso 9: Bloqueo automático

Se inició el servicio:

```bash
sudo systemctl restart ai-firewall
sudo systemctl status ai-firewall
```

Luego desde VM2 se ejecutó:

```bash
sudo nmap -Pn -sS -p 1-1000 192.168.10.10
sudo hping3 -S -p 80 -c 2000 -i u10000 192.168.10.10
```

En VM1 se verificó:

```bash
sudo nft list set inet filter ia_blocklist
sudo journalctl -u ai-firewall --no-pager | tail -40
```

Resultado:

```text
10.10.10.20 agregado a ia_blocklist
IP=10.10.10.20 pred=attack
BLOQUEADO por IA: 10.10.10.20
```

---

## 6. Ejemplo de ataque demostrado

### Ataque: SYN flood controlado

Desde VM2 UbuntuAtacante:

```bash
sudo hping3 -S -p 80 -c 2000 -i u10000 192.168.10.10
```

Este comando envía paquetes TCP SYN al puerto 80 del servidor víctima.

La IA analiza el comportamiento y detecta:

- Alta cantidad de paquetes TCP.
- Alta proporción de SYN.
- Tráfico repetitivo hacia el mismo objetivo.
- Patrón compatible con ataque.

Resultado del motor IA:

```text
IP=10.10.10.20 pred=attack conf=93.74%
BLOQUEADO por IA: 10.10.10.20
```

Resultado en nftables:

```text
elements = { 10.10.10.20 expires ... }
```

Explicación:

> La máquina atacante intentó generar tráfico SYN hacia el servidor víctima. El motor IA clasificó ese comportamiento como ataque y agregó automáticamente la IP `10.10.10.20` al set `ia_blocklist`, bloqueando su tráfico durante una hora.

---

## 7. Cómo explicar este repositorio al ingeniero

Puede explicarse así:

> Este repositorio contiene la implementación completa del firewall con IA. Primero se configuró un firewall clásico con `nftables`. Luego se capturó tráfico normal y tráfico de ataque usando `tcpdump`. A partir de esas capturas se generaron características numéricas con `extract_features.py`, se construyó el dataset y se entrenó un modelo Random Forest con `train_model.py`. Finalmente, el script `ai_firewall.py` carga el modelo entrenado, analiza tráfico en vivo y bloquea automáticamente la IP atacante usando `ia_blocklist` en `nftables`. El servicio `ai-firewall.service` permite ejecutar todo como un servicio del sistema.

---

## 8. Comandos principales para demostrar

### Ver firewall

```bash
sudo nft list ruleset
```

### Ver lista de bloqueo IA

```bash
sudo nft list set inet filter ia_blocklist
```

### Ver logs de paquetes descartados

```bash
sudo journalctl -k | grep NFT-DROP | tail -20
```

### Ver dataset

```bash
python3 - << 'PY'
import pandas as pd
df = pd.read_csv("data/dataset.csv")
print(df.shape)
print(df.isna().sum())
print(df["label"].value_counts())
PY
```

### Ver métricas del modelo

```bash
cat models/metrics_comparison.csv
```

### Ver servicio IA

```bash
sudo systemctl status ai-firewall
```

### Ver logs de IA

```bash
sudo journalctl -u ai-firewall --no-pager | tail -40
```

---

## 9. Archivos generados en la VM

Los archivos generados durante la ejecución real del laboratorio son:

```text
data/traffic-normal.pcap
data/traffic-attack.pcap
data/normal.csv
data/attack.csv
data/dataset.csv
models/firewall_ai_model.joblib
models/scaler.joblib
models/metrics_comparison.csv
models/feature_importance.csv
```

Estos archivos pueden no estar incluidos en el repositorio por tamaño o porque se generan durante la práctica. Sin embargo, el procedimiento para generarlos está documentado en este README.

---

## 10. Conclusión

El laboratorio demuestra la integración entre un firewall tradicional y un modelo de IA. `nftables` se encarga del filtrado y bloqueo, mientras que el modelo Random Forest analiza características del tráfico para identificar ataques. La prueba final demuestra que una IP atacante puede ser detectada y bloqueada automáticamente, cumpliendo el flujo:

```text
Ataque detectado → Clasificación IA → Bloqueo en nftables → Evidencia en logs
```

