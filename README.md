[README.md](https://github.com/user-attachments/files/32128164/README.md)
# NEXUS // Network Analyzer

NEXUS è un tool per analisi di rete e sicurezza locale, sviluppato in Python con interfaccia grafica in `customtkinter`. L'applicazione permette di eseguire controlli di rete, rilevamento Wi‑Fi, cattura di metadati di pacchetti e verifica di password contro una lista locale di hash SHA-256.

## Funzioni principali

- Scansione avanzata di reti con Nmap
- Rilevamento delle reti Wi‑Fi vicine tramite Windows `netsh`
- Modalità monitor Wi‑Fi (Linux/macOS, per metadati 802.11)
- Cattura di pacchetti con esclusione del payload dei dati
- Controllo password locale con wordlist esterna
- Interfaccia grafica dedicata per eseguire tutti i moduli in modo semplice

## Screenshot / UI

L'app usa una dashboard dark-themed con sidebar e pannello di output live.

## Requisiti

- Python 3.10+
- Windows (per la scansione Wi‑Fi e la parte GUI)
- Nmap installato e disponibile nel PATH
- Dipendenze Python:
  - `customtkinter`
  - `python-nmap`
  - `scapy`

## Installazione

1. Clona il repository:

```bash
git clone https://github.com/<tuo-username>/<tuo-repo>.git
cd <tuo-repo>
```

2. Crea un ambiente virtuale (opzionale ma consigliato):

```bash
python -m venv .venv
.venv\Scripts\activate
```

3. Installa le dipendenze:

```bash
pip install -r requirements.txt
```

4. Assicurati che `nmap.exe` sia installato e disponibile nel PATH di sistema.

## Esecuzione

Avvia l'applicazione con:

```bash
python network_analysis.py
```

## Utilizzo

### 1) Nmap Advanced Full Scan

Inserisci un indirizzo IP, hostname, CIDR o target Nmap e avvia la scansione.

Esempi:

- `192.168.1.0/24`
- `192.168.1.10`
- `scanme.nmap.org`

### 2) Nearby Wi‑Fi Scanner

Mostra le reti Wi‑Fi disponibili e alcune informazioni utili come:

- SSID
- BSSID
- segnale
- canale
- protocollo e tipo di accesso

### 3) Monitor Mode Wi‑Fi

Supportato su Linux/macOS per raccogliere metadati 802.11, senza salvare il payload.

> Questa funzionalità richiede permessi adeguati e un adattatore compatibile con monitor mode.

### 4) Packet Capture

Cattura solo metadati IP (src/dst/protocol), senza salvare i contenuti dei pacchetti.

> Richiede permessi amministrativi e, in Windows, spesso `Npcap` o driver compatibili.

### 5) Password Hash Check

Verifica una password contro una lista locale di hash SHA‑256. Il controllo viene eseguito localmente senza inviare dati esternamente.

## Struttura del progetto

```text
.
├── network_analysis.py
├── requirements.txt
├── common_passwords.txt
├── create_exe.py
├── MONITOR_MODE_WIFI.md
├── NetworkAnalyzer.spec
├── build/
├── dist/
└── README.md
```

## Build EXE

Per creare un file eseguibile standalone puoi usare PyInstaller:

```bash
python -m PyInstaller --onefile --windowed --name NetworkAnalyzer --distpath dist --workpath build/NetworkAnalyzer_updated --specpath . network_analysis.py
```

Il progetto include anche un file `create_exe.py` per automatizzare la generazione del binario.

## Avviso importante

Questo progetto è stato creato a scopo educativo e di analisi di rete in ambienti autorizzati. L'uso in reti o dispositivi non di proprietà dell'utente può violare leggi, policy aziendali o accordi di sicurezza.

Usa lo strumento in modo responsabile e conforme alle normative applicabili.

## Licenza

Questo progetto non include ancora una licenza specifica. Se vuoi pubblicarlo su GitHub, è consigliabile aggiungere una licenza come MIT o GPL, in base al tuo utilizzo.

## Autore

Questo repository può essere adattato e personalizzato secondo le tue esigenze.

## Contatti / contribuzione

Se vuoi migliorare il progetto, apri una PR o invia una proposta di modifica.
