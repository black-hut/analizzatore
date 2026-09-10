
import asyncio
import socket
import subprocess
import platform
import threading
import ipaddress
import psutil
import customtkinter as ctk
from bleak import BleakScanner

# Fix per BLE in app --windowed (STA thread)
try:
    from bleak.backends.winrt.util import allow_sta
    allow_sta()
except ImportError:
    pass

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

# ═══════════════════════════════════════════════════════
#  FUNZIONI DI SCAN
# ═══════════════════════════════════════════════════════

def scan_bluetooth():
    async def _scan():
        return await BleakScanner.discover(timeout=8.0)
    devices = asyncio.run(_scan())
    if not devices:
        return "Nessun dispositivo BLE trovato."
    return "\n".join(f"  {d.name or 'Sconosciuto'} - {d.address}" for d in devices)

def scan_wifi():
    try:
        output = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
            text=True, errors='replace'
        )
        return output
    except subprocess.CalledProcessError:
        try:
            output = subprocess.check_output(
                ['netsh', 'wlan', 'show', 'networks'],
                text=True, errors='replace'
            )
            return output
        except Exception as e:
            return f"Errore: {e}"

def scan_local_ips():
    lines = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                lines.append(f"  {iface}: {addr.address}")
    return "\n".join(lines) if lines else "Nessun IP trovato."

def ping_sweep():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        return "Impossibile ottenere IP locale."
    network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
    hosts = []
    for host in network.hosts():
        try:
            result = subprocess.run(
                ['ping', '-n', '1', '-w', '300', str(host)],
                capture_output=True, text=True, timeout=2
            )
            if 'TTL=' in result.stdout or 'TTL=' in result.stdout:
                hosts.append(str(host))
        except Exception:
            pass
    if not hosts:
        return "Nessun host attivo trovato."
    return f"Host attivi ({len(hosts)}):\n" + "\n".join(f"  {h}" for h in hosts)

def system_info():
    cpu = psutil.cpu_percent(interval=1)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage('C:\\')
    lines = [
        f"  Hostname:    {platform.node()}",
        f"  Sistema:     {platform.system()} {platform.release()}",
        f"  Python:      {platform.python_version()}",
        f"  CPU:         {psutil.cpu_count(logical=True)} core, utilizzo {cpu}%",
        f"  RAM:         {mem.percent}% ({mem.available // (1024*1024)} MB liberi)",
        f"  Disco C:     {disk.percent}% usato",
    ]
    return "\n".join(lines)

def port_scan(target, ports=None):
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3389, 8080]
    lines = []
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((target, port))
            s.close()
            if result == 0:
                lines.append(f"  {target}:{port}  →  APERTA")
        except Exception:
            pass
    if not lines:
        return f"Nessuna porta aperta su {target}."
    return f"Porte aperte su {target}:\n" + "\n".join(lines)

# ═══════════════════════════════════════════════════════
#  GUI (CustomTkinter)
# ═══════════════════════════════════════════════════════

class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Network Analyzer")
        self.geometry("750x550")
        self.minsize(600, 400)

        # ── Header ──
        header = ctk.CTkFrame(self, fg_color="transparent")
        header.pack(fill="x", padx=15, pady=(10, 5))
        ctk.CTkLabel(header, text="🔍 Network Analyzer",
                     font=("Segoe UI", 20, "bold")).pack(side="left")

        # ── Pulsanti ──
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=5)

        buttons = [
            ("🔵 Bluetooth", self.run_bluetooth),
            ("📶 WiFi", self.run_wifi),
            ("🌐 IP Locali", self.run_ips),
            ("📡 Ping Sweep", self.run_ping),
            ("💻 Sistema", self.run_sysinfo),
        ]
        for text, cmd in buttons:
            ctk.CTkButton(btn_frame, text=text, command=cmd,
                          width=120, height=35, corner_radius=8).pack(side="left", padx=4)

        # ── Port Scan ──
        port_frame = ctk.CTkFrame(self, fg_color="transparent")
        port_frame.pack(fill="x", padx=15, pady=5)
        ctk.CTkLabel(port_frame, text="Port Scan:").pack(side="left")
        self.port_entry = ctk.CTkEntry(port_frame, width=160, placeholder_text="192.168.1.1")
        self.port_entry.pack(side="left", padx=8)
        ctk.CTkButton(port_frame, text="🔍 Scan", command=self.run_portscan,
                      width=80, height=32, corner_radius=8).pack(side="left")

        # ── Area risultati ──
        self.text_frame = ctk.CTkFrame(self)
        self.text_frame.pack(fill="both", expand=True, padx=15, pady=5)
        self.text = ctk.CTkTextbox(self.text_frame, font=("Consolas", 11), wrap="word")
        self.text.pack(fill="both", expand=True, padx=5, pady=5)

        # ── Barra di stato ──
        self.status = ctk.CTkLabel(self, text="Pronto", anchor="w")
        self.status.pack(fill="x", side="bottom", padx=15, pady=(0, 8))

    def _run_bg(self, func, label):
        """Esegue la funzione in un thread per non bloccare la GUI."""
        self.status.configure(text=f"⏳ {label}...")

        def worker():
            try:
                result = func()
            except Exception as e:
                result = f"Errore: {e}"
            self.after(0, lambda: self._show_result(label, result))

        threading.Thread(target=worker, daemon=True).start()

    def _show_result(self, label, result):
        self.text.insert("end", f"\n{'═' * 50}\n  {label}\n{'═' * 50}\n{result}\n")
        self.text.see("end")
        self.status.configure(text="✓ Completato")

    def run_bluetooth(self):  self._run_bg(scan_bluetooth, "Bluetooth BLE")
    def run_wifi(self):       self._run_bg(scan_wifi, "Reti WiFi")
    def run_ips(self):        self._run_bg(scan_local_ips, "IP Locali")
    def run_ping(self):       self._run_bg(ping_sweep, "Ping Sweep")
    def run_sysinfo(self):    self._run_bg(system_info, "Info Sistema")

    def run_portscan(self):
        target = self.port_entry.get().strip()
        if not target:
            return
        self._run_bg(lambda: port_scan(target), f"Port Scan {target}")


if __name__ == "__main__":
    app = App()
    app.mainloop()
