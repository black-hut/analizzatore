import hashlib
import ipaddress
import re
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import customtkinter as ctk

try:
    import nmap
except ImportError:
    nmap = None

try:
    from scapy.all import Dot11, IP, RadioTap, sniff
except ImportError:
    Dot11 = None
    IP = None
    RadioTap = None
    sniff = None


ctk.set_appearance_mode('dark')
ctk.set_default_color_theme('dark-blue')


def scan_network(target):
    """Esegue una scansione Nmap avanzata su tutte le porte TCP."""
    target = target.strip()
    if not target:
        return 'Inserisci un IP, hostname o intervallo di rete.'
    if len(target) > 255 or not re.fullmatch(r'[A-Za-z0-9.:%/_,-]+', target):
        return 'Target non valido. Usa un IP, hostname, CIDR o intervallo Nmap.'
    if nmap is None:
        return 'python-nmap non installato. Installa il pacchetto Python e Nmap per Windows.'

    try:
        scanner = nmap.PortScanner()
        scanner.scan(
            hosts=target,
            ports='1-65535',
            arguments='-sS -T5 -A -v --host-timeout 120s'
        )
    except nmap.PortScannerError as error:
        return f'Errore Nmap: {error}\nVerifica che nmap.exe sia installato e nel PATH.'
    except OSError as error:
        return f'Impossibile avviare Nmap: {error}'

    if not scanner.all_hosts():
        return f'Nessun host trovato per: {target}'

    rows = [f'NMAP NETWORK SCAN  /  {target}', '']
    for host in scanner.all_hosts():
        host_data = scanner[host]
        hostname = host_data.hostname() or '--'
        addresses = host_data.get('addresses', {})
        mac_address = addresses.get('mac', '--')
        device_name = '--'
        os_matches = host_data.get('osmatch', [])
        if os_matches:
            device_name = os_matches[0].get('name', '--')
        rows.extend([
            f'Host: {host} ({hostname})',
            f'Stato: {host_data.state()}',
            f'MAC: {mac_address}',
            f'Dispositivo/OS: {device_name}'
        ])
        for protocol in host_data.all_protocols():
            rows.append(f'Protocollo: {protocol}')
            for port in sorted(host_data[protocol]):
                port_data = host_data[protocol][port]
                service = port_data.get('name', '--')
                product = port_data.get('product', '')
                version = port_data.get('version', '')
                details = ' '.join(value for value in (service, product, version) if value)
                state = port_data.get('state', '--')
                if state in ('open', 'open|filtered'):
                    rows.append(f'  Porta {port}: {state}  {details}')
        rows.append('')
    return '\n'.join(rows)


def capture_packets(count=10):
    """Cattura solo metadati IP, senza conservare il contenuto dei pacchetti."""
    if sniff is None or IP is None:
        return 'Scapy non installato. Installa Scapy e Npcap per Windows.'

    packets = []

    def packet_callback(packet):
        if packet.haslayer(IP):
            packets.append(
                f'  {packet[IP].src} -> {packet[IP].dst} '
                f'({packet[IP].proto})'
            )

    try:
        sniff(prn=packet_callback, count=count, store=False, timeout=15)
    except PermissionError:
        return 'Permessi insufficienti: avvia NEXUS come amministratore e verifica Npcap.'
    except OSError as error:
        return f'Errore cattura pacchetti: {error}'

    if not packets:
        return 'Nessun pacchetto IP catturato nel periodo di ascolto.'
    return 'PACKET CAPTURE  /  METADATI IP\n\n' + '\n'.join(packets)


WIFI_OUIS = {
    '00:1C:42': 'Hikvision (possibile)',
    '28:57:BE': 'Dahua (possibile)',
    'D8:1C:79': 'Tuya (possibile)',
    '00:62:6E': 'Foscam (possibile)',
    '2C:AA:8E': 'Wyze (possibile)',
    'B0:09:DA': 'Ring (possibile)',
    '20:0C:C8': 'Netgear (possibile)',
}


def _wifi_vendor(mac):
    normalized = mac.upper().replace('-', ':')
    prefix = normalized[:8]
    return WIFI_OUIS.get(prefix, 'Vendor non mappato')


def _set_monitor_channel(interface, channel):
    """Cambia canale senza trasmettere; supporta Linux e macOS."""
    if sys.platform.startswith('linux'):
        command = ['iw', 'dev', interface, 'set', 'channel', str(channel)]
    elif sys.platform == 'darwin':
        airport = (
            '/System/Library/PrivateFrameworks/Apple80211.framework/'
            'Versions/Current/Resources/airport'
        )
        command = [airport, '-c', str(channel)]
    else:
        return False
    try:
        return subprocess.run(
            command, capture_output=True, text=True, timeout=3
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def monitor_mode_wifi_scan(interface, duration=30):
    """Ascolta Dot11 in monitor mode e raccoglie solo metadati radio."""
    if sniff is None or Dot11 is None or RadioTap is None:
        return 'Scapy non installato. Installa Scapy e configura Npcap/Npcap-compatible.'
    if not interface or duration < 1:
        return 'Indica un\'interfaccia monitor valida e una durata positiva.'
    if sys.platform not in ('darwin', 'linux'):
        return 'La modalità monitor con channel hopping è supportata da questo modulo su Linux/macOS.'

    devices = {}
    started = time.monotonic()

    def packet_callback(packet):
        if not packet.haslayer(Dot11):
            return
        dot11 = packet[Dot11]
        transmitter = (dot11.addr2 or '').upper()
        if not transmitter or transmitter == 'FF:FF:FF:FF:FF:FF':
            return
        frame_type = dot11.type
        subtype = dot11.subtype
        if frame_type != 0 or subtype not in (4, 8, 5):
            return
        kind = {4: 'Probe Request', 5: 'Probe Response', 8: 'Beacon'}[subtype]
        ssid = '<non trasmesso>'
        if subtype in (5, 8) and packet.haslayer(Dot11):
            payload = bytes(dot11.payload)
            match = re.search(b'\x00([\x00-\xff]{0,32})\x01', payload)
            if match:
                ssid = match.group(1).decode('utf-8', errors='replace') or '<vuoto>'
        rssi = 'N/D'
        if packet.haslayer(RadioTap) and getattr(packet[RadioTap], 'dBm_AntSignal', None) is not None:
            rssi = f'{packet[RadioTap].dBm_AntSignal} dBm'
        devices[transmitter] = {
            'mac': transmitter, 'vendor': _wifi_vendor(transmitter),
            'type': kind, 'ssid': ssid, 'rssi': rssi,
            'last_seen': time.strftime('%H:%M:%S')
        }

    try:
        while time.monotonic() - started < duration:
            for channel in range(1, 14):
                if time.monotonic() - started >= duration:
                    break
                _set_monitor_channel(interface, channel)
                sniff(
                    iface=interface, prn=packet_callback, store=False,
                    timeout=min(1.0, max(0.1, duration - (time.monotonic() - started)))
                )
    except PermissionError:
        return 'Permessi insufficienti: avvia la cattura con privilegi adeguati.'
    except (OSError, ValueError) as error:
        return f'Errore monitor mode su {interface}: {error}'

    rows = [
        f'WIRELESS MONITOR SCAN  /  {interface}',
        f'Durata: {duration}s | Canali: 1-13 | Dispositivi: {len(devices)}',
        '',
        f"{'MAC TRANSMITTER':<18} {'VENDOR/OUI':<24} {'TIPO':<16} "
        f"{'RSSI':<10} SSID",
        '-' * 100
    ]
    rows.extend(
        f"{device['mac']:<18} {device['vendor'][:23]:<24} "
        f"{device['type']:<16} {device['rssi']:<10} {device['ssid']}"
        for device in sorted(devices.values(), key=lambda item: item['mac'])
    )
    rows.extend([
        '',
        'Solo metadati 802.11: nessun payload, autenticazione o pacchetto trasmesso.',
        'Un OUI indicato come possibile vendor non identifica con certezza il modello.'
    ])
    return '\n'.join(rows)


def scan_nearby_wifi():
    """Elenca le reti Wi-Fi visibili dall'adattatore locale."""
    try:
        networks_result = subprocess.run(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            capture_output=True, text=True, errors='replace', timeout=30
        )
        interfaces_result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True, text=True, errors='replace', timeout=15
        )
    except (OSError, subprocess.SubprocessError) as error:
        return f'Impossibile eseguire la scansione Wi-Fi: {error}'

    output = networks_result.stdout
    if networks_result.returncode != 0 or not output.strip():
        return 'Nessuna rete Wi-Fi rilevata. Verifica adattatore, WLAN e autorizzazione Posizione Windows.'

    active_ssid = '--'
    active_ip = '--'
    interface_text = interfaces_result.stdout
    ssid_match = re.search(r'^\s*SSID\s*:\s*(?!BSSID)(.+)$', interface_text, re.IGNORECASE | re.MULTILINE)
    if ssid_match:
        active_ssid = ssid_match.group(1).strip()
        try:
            host_addresses = socket.gethostbyname_ex(socket.gethostname())[2]
            active_ip = next(
                address for address in host_addresses
                if ipaddress.ip_address(address).version == 4 and not address.startswith('127.')
            )
        except (socket.gaierror, StopIteration, ValueError):
            active_ip = '--'

    networks = []
    current = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        ssid_match = re.match(r'SSID\s+\d+\s*:\s*(.*)', line, re.IGNORECASE)
        if ssid_match:
            if current:
                networks.append(current)
            current = {
                'ssid': ssid_match.group(1).strip() or '<rete nascosta>',
                'bssid': '--', 'signal': '--', 'channel': '--',
                'auth': '--', 'encryption': '--', 'radio': '--'
            }
            continue
        if current is None:
            continue
        patterns = (
            ('bssid', r'BSSID\s+\d+\s*:\s*(.+)'),
            ('signal', r'(?:Signal|Segnale)\s*:\s*(\d+%?)'),
            ('channel', r'(?:Channel|Canale)\s*:\s*(\d+)'),
            ('auth', r'(?:Authentication|Autenticazione)\s*:\s*(.+)'),
            ('encryption', r'(?:Encryption|Crittografia)\s*:\s*(.+)'),
            ('radio', r'(?:Radio type|Tipo di radio)\s*:\s*(.+)')
        )
        for field, pattern in patterns:
            match = re.match(pattern, line, re.IGNORECASE)
            if match:
                current[field] = match.group(1).strip()
                break
    if current:
        networks.append(current)

    if not networks:
        return 'Nessuna rete Wi-Fi rilevata. Verifica il servizio WLAN e la Posizione di Windows.'

    rows = [
        'NEARBY WI-FI SCANNER',
        'Raggio: massimo consentito dall\'adattatore Wi-Fi',
        f'Rete connessa: {active_ssid}  |  IP locale: {active_ip}',
        '',
        f"{'SSID':<24} {'BSSID':<18} {'SEGNALE':<9} {'CANALE':<8} "
        f"{'PROTOCOLLO':<16} {'ACCESSO':<13} IP",
        '-' * 116
    ]
    for network in networks:
        auth = network['auth']
        access = 'APERTA/PUBBLICA' if auth.lower() in ('open', 'aperta', 'none', 'nessuna') else 'PROTETTA/PRIVATA'
        network_ip = active_ip if network['ssid'] == active_ssid else 'N/D'
        protocol = network['radio'] if network['radio'] != '--' else network['encryption']
        rows.append(
            f"{network['ssid'][:23]:<24} {network['bssid']:<18} "
            f"{network['signal']:<9} {network['channel']:<8} "
            f"{protocol[:15]:<16} {access:<13} {network_ip}"
        )
    rows.extend([
        '',
        'Nota: le reti non connesse non espongono il proprio IP tramite la scansione Wi-Fi.',
        'Per questo motivo l\'IP e mostrato solo per la rete attiva; N/D significa non disponibile.'
    ])
    return '\n'.join(rows)


def _password_list_path():
    candidates = [
        Path(sys.executable).resolve().parent / 'common_passwords.txt',
        Path(__file__).resolve().parent / 'common_passwords.txt',
        Path(__file__).resolve().parent / 'Nuova cartella' / 'common_passwords.txt',
    ]
    if getattr(sys, 'frozen', False):
        candidates.append(Path(getattr(sys, '_MEIPASS', '')) / 'common_passwords.txt')
    return next((path for path in candidates if path.is_file()), None)


def _load_password_hashes():
    password_file = _password_list_path()
    if password_file is None:
        return None, None
    try:
        passwords = {
            hashlib.sha256(line.strip().encode('utf-8')).hexdigest()
            for line in password_file.read_text(encoding='utf-8-sig').splitlines()
            if line.strip() and not line.lstrip().startswith('#')
        }
    except OSError as error:
        return None, error
    return passwords, password_file


def check_password(password):
    """Confronta localmente l'hash SHA-256 con la wordlist esterna."""
    if not password:
        return 'Nessuna password inserita.'
    password_hashes, password_file = _load_password_hashes()
    if password_hashes is None:
        return 'File common_passwords.txt non trovato o non leggibile.'
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    if password_hash in password_hashes:
        return f'PASSWORD NON SICURA: trovata in {password_file.name} ({len(password_hashes)} voci).'
    if len(password) < 12:
        return 'Password non trovata nel file, ma troppo corta: usa almeno 12 caratteri.'
    return f'Password non trovata in {password_file.name} ({len(password_hashes)} voci).'


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title('NEXUS // Network Analyzer')
        self.geometry('1060x680')
        self.minsize(760, 500)
        self.configure(fg_color='#080d18')
        self.scan_running = False

        sidebar = ctk.CTkFrame(self, width=220, corner_radius=0, fg_color='#0d1424')
        sidebar.pack(side='left', fill='y')
        sidebar.pack_propagate(False)

        ctk.CTkLabel(
            sidebar, text='NEXUS', text_color='#55e6ff',
            font=('Segoe UI', 27, 'bold')
        ).pack(anchor='w', padx=24, pady=(28, 0))
        ctk.CTkLabel(
            sidebar, text='NETWORK INTELLIGENCE', text_color='#71809a',
            font=('Segoe UI', 10, 'bold')
        ).pack(anchor='w', padx=26, pady=(0, 34))

        ctk.CTkLabel(
            sidebar, text='MODULES', text_color='#71809a',
            font=('Segoe UI', 10, 'bold')
        ).pack(anchor='w', padx=26, pady=(20, 8))
        action_frame = ctk.CTkScrollableFrame(sidebar, fg_color='transparent')
        action_frame.pack(fill='both', expand=True, padx=4)
        actions = [
              ('Nmap Advanced Full Scan', self.run_nmap),
            ('Nearby Wi-Fi Scanner', self.run_wifi_scan),
            ('Monitor Mode Wi-Fi', self.run_monitor_wifi),
            ('Packet Capture', self.run_capture),
            ('Password Hash Check', self.run_password_check),
        ]
        for label, command in actions:
            ctk.CTkButton(
                action_frame, text=label, command=command, anchor='w',
                height=36, corner_radius=8, fg_color='transparent',
                hover_color='#17253b', text_color='#d7e5f5',
                font=('Segoe UI', 11)
            ).pack(fill='x', padx=6, pady=2)

        ctk.CTkButton(
            sidebar, text='Clear console', command=self.clear_results,
            height=36, corner_radius=8, fg_color='#182337',
            hover_color='#223653', text_color='#a9bdd6'
        ).pack(side='bottom', fill='x', padx=14, pady=(0, 58))
        ctk.CTkLabel(
            sidebar, text='v3.0  /  READY', text_color='#4c5e77',
            font=('Segoe UI', 10)
        ).pack(side='bottom', anchor='w', padx=25, pady=22)

        content = ctk.CTkFrame(self, fg_color='#080d18', corner_radius=0)
        content.pack(side='left', fill='both', expand=True)

        header = ctk.CTkFrame(content, fg_color='transparent')
        header.pack(fill='x', padx=30, pady=(28, 8))
        ctk.CTkLabel(
            header, text='Network command center', text_color='#f0f6ff',
            font=('Segoe UI', 25, 'bold')
        ).pack(side='left')
        ctk.CTkLabel(
            header, text='●  READY', text_color='#5df2b1',
            font=('Segoe UI', 11, 'bold')
        ).pack(side='right', pady=8)
        ctk.CTkLabel(
            content, text='NEXUS network tools are ready.',
            text_color='#70829c', font=('Segoe UI', 12)
        ).pack(anchor='w', padx=32)

        target_card = ctk.CTkFrame(content, fg_color='#101a2c', corner_radius=12)
        target_card.pack(fill='x', padx=30, pady=(24, 14))
        ctk.CTkLabel(
                target_card, text='NMAP FULL / T5', text_color='#55e6ff',
            font=('Segoe UI', 11, 'bold')
        ).pack(side='left', padx=(18, 12), pady=16)
        self.target_entry = ctk.CTkEntry(
            target_card, width=260, height=36,
            placeholder_text='IP, hostname o rete CIDR',
            border_color='#294261', fg_color='#0a1220'
        )
        self.target_entry.pack(side='left', pady=12)
        ctk.CTkButton(
                target_card, text='Run Full Scan  ->', command=self.run_nmap,
            width=130, height=36, corner_radius=8,
            fg_color='#1c9fbc', hover_color='#27bedc',
            text_color='#06121c', font=('Segoe UI', 12, 'bold')
        ).pack(side='left', padx=10)

        monitor_card = ctk.CTkFrame(content, fg_color='#101a2c', corner_radius=12)
        monitor_card.pack(fill='x', padx=30, pady=(0, 14))
        ctk.CTkLabel(
            monitor_card, text='MONITOR MODE', text_color='#55e6ff',
            font=('Segoe UI', 11, 'bold')
        ).pack(side='left', padx=(18, 12), pady=12)
        self.monitor_entry = ctk.CTkEntry(
            monitor_card, width=180, height=34,
            placeholder_text='wlan0 / en0'
        )
        self.monitor_entry.pack(side='left', pady=10)
        ctk.CTkButton(
            monitor_card, text='Scan 30s', command=self.run_monitor_wifi,
            width=110, height=34, corner_radius=8,
            fg_color='#253b56', hover_color='#315271',
            text_color='#d7e5f5', font=('Segoe UI', 11, 'bold')
        ).pack(side='left', padx=10)

        self.text_frame = ctk.CTkFrame(content, fg_color='#101a2c', corner_radius=12)
        self.text_frame.pack(fill='both', expand=True, padx=30, pady=(24, 12))
        ctk.CTkLabel(
            self.text_frame, text='LIVE OUTPUT', text_color='#71809a',
            font=('Segoe UI', 10, 'bold')
        ).pack(anchor='w', padx=18, pady=(14, 0))
        self.text = ctk.CTkTextbox(
            self.text_frame, font=('Cascadia Mono', 12), wrap='word',
            fg_color='#0a1220', text_color='#b9cce1', corner_radius=8
        )
        self.text.pack(fill='both', expand=True, padx=12, pady=10)
        self.text.insert('end', 'NEXUS initialized. No modules are active.\n')

        self.status = ctk.CTkLabel(
            content, text='READY  /  Select a module to begin',
            text_color='#6f829e', anchor='w', font=('Segoe UI', 11)
        )
        self.status.pack(fill='x', padx=32, pady=(0, 14))

    def clear_results(self):
        self.text.delete('1.0', 'end')
        self.status.configure(text='READY  /  Console cleared')

    def _run_bg(self, function, label):
        if self.scan_running:
            self.status.configure(text='BUSY  /  Attendi il completamento del modulo corrente')
            return
        self.scan_running = True
        self.status.configure(text=f'WORKING  /  {label}...')

        def worker():
            try:
                result = function()
            except Exception as error:
                result = f'Errore {label}: {error}'
            self.after(0, lambda: self._show_result(label, result))

        threading.Thread(target=worker, daemon=True).start()

    def _show_result(self, label, result):
        self.text.insert('end', f"\n{'=' * 64}\n  {label.upper()}\n{'=' * 64}\n{result}\n")
        self.text.see('end')
        self.scan_running = False
        self.status.configure(text=f'READY  /  {label} completed')

    def run_nmap(self):
        target = self.target_entry.get().strip()
        self._run_bg(lambda: scan_network(target), 'Nmap Network Scan')

    def run_wifi_scan(self):
        self._run_bg(scan_nearby_wifi, 'Nearby Wi-Fi Scanner')

    def run_monitor_wifi(self):
        interface = self.monitor_entry.get().strip()
        self._run_bg(
            lambda: monitor_mode_wifi_scan(interface),
            'Monitor Mode Wi-Fi'
        )

    def run_capture(self):
        self._run_bg(capture_packets, 'Packet Capture')

    def run_password_check(self):
        dialog = ctk.CTkInputDialog(
            text='Inserisci la password da verificare localmente:',
            title='Password Hash Check'
        )
        password = dialog.get_input()
        if password is not None:
            self._run_bg(lambda: check_password(password), 'Password Hash Check')


if __name__ == '__main__':
    app = App()
    app.mainloop()
