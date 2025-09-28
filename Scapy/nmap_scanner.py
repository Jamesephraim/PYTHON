#!/usr/bin/env python3
"""
network_scanner_gui_with_types.py

Extends the previous network scanner to show a guessed device type
(Android / Windows / Linux / IoT / Router / Unknown) in the GUI.
"""

import sys
import platform
import subprocess
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import ipaddress
import time
import re

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog
except Exception:
    print("Tkinter required. On Linux: sudo apt install python3-tk")
    raise

# ------- Configuration -------
PING_TIMEOUT = 1.0
THREAD_WORKERS = 200
COMMON_PORTS = [22, 23, 25, 53, 67, 68, 80, 110, 139, 143, 161, 389, 443, 445, 3306, 3389, 5900, 8080, 8443]
SOCKET_TIMEOUT = 0.6

# ------- Utility functions -------

def get_default_local_network():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.ip_network(local_ip + "/24", strict=False)
        return str(network)
    except Exception:
        return None

def ping_host(ip):
    plat = platform.system().lower()
    if 'windows' in plat:
        args = ["ping", "-n", "1", "-w", str(int(PING_TIMEOUT*1000)), str(ip)]
    else:
        args = ["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), str(ip)]
    try:
        res = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def get_ttl(ip):
    """
    Perform a single ping and try to extract TTL value.
    Returns int TTL or None.
    """
    plat = platform.system().lower()
    try:
        if 'windows' in plat:
            # -n 1 send 1, -w timeout in ms
            p = subprocess.run(["ping", "-n", "1", "-w", str(int(PING_TIMEOUT*1000)), ip],
                               capture_output=True, text=True, timeout=3)
        else:
            p = subprocess.run(["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip],
                               capture_output=True, text=True, timeout=3)
        out = p.stdout.lower()
        m = re.search(r'ttl[=|:](\d+)', out)
        if m:
            return int(m.group(1))
    except Exception:
        pass
    return None

def get_arp_table():
    plat = platform.system().lower()
    arp = {}
    try:
        if 'windows' in plat:
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            out = p.stdout
            for line in out.splitlines():
                line = line.strip()
                m = re.match(r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F\-]{17})', line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace('-', ':').lower()
                    arp[ip] = mac
        else:
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True)
            out = p.stdout
            for line in out.splitlines():
                ip_m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)', line)
                mac_m = re.search(r'([0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2}[:\-][0-9a-fA-F]{2})', line)
                if ip_m and mac_m:
                    ip = ip_m.group(1)
                    mac = mac_m.group(1).replace('-', ':').lower()
                    arp[ip] = mac
    except Exception:
        pass
    return arp

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""

def scan_port(ip, port, timeout=SOCKET_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((str(ip), int(port)))
            return True
    except Exception:
        return False

# ------- Device type detection (heuristic) -------

def detect_device_type(open_ports, hostname, ttl, mac):
    """
    Heuristic classification:
    - Phone/Android if hostname suggests mobile OR ports typical for phones (adb 5555).
    - Router if TTL very high (255) or typical gateway addresses (.1) or MAC vendor hints (not implemented).
    - Windows if TTL >= 128 or RDP port open.
    - Linux/Unix if TTL >= 64 or SSH open.
    - IoT/Camera if ports like 554 (RTSP), 8554, 1883 (MQTT), telnet (23) open.
    - Default Unknown.
    Returns (label, emoji).
    """
    h = (hostname or "").lower()

    # quick phone detection by hostname
    phone_keywords = ["android", "pixel", "galaxy", "iphone", "mobile", "phone"]
    if any(k in h for k in phone_keywords):
        return ("Phone (Android/iOS)", "📱")

    # check ports
    ports = set(open_ports or [])
    if 5555 in ports:  # adb
        return ("Android (ADB)", "🤖")
    if 3389 in ports:
        return ("Windows PC", "🖥️")
    if 22 in ports and 3389 not in ports:
        # likely linux/unix if ssh present
        return ("Linux/Unix", "💻")
    if 554 in ports or 8554 in ports or 8200 in ports or 1900 in ports or 1883 in ports:
        # common camera/IoT ports (rtsp, upnp, mqtt)
        # if HTTP banner contains "camera" would be stronger but we don't fetch banners here
        return ("IoT / Camera", "📷")
    if 23 in ports or 2323 in ports:
        return ("IoT / Embedded (telnet)", "🔌")

    # TTL fallback
    if ttl:
        if ttl >= 200:
            return ("Router / Networking Device", "📶")
        if ttl >= 128:
            return ("Windows PC (guess)", "🖥️")
        if ttl >= 64:
            return ("Linux/Unix (guess)", "💻")

    # MAC / IP heuristics: if .1 it's often a gateway/router
    if mac and mac != "" and mac.endswith(":01"):  # weak heuristic (not reliable)
        return ("Router (MAC hint)", "📶")

    # If hostname contains 'router' or 'gateway' or 'switch'
    if any(k in h for k in ["router", "gateway", "switch", "ap"]):
        return ("Router", "📶")

    return ("Unknown", "❓")

# ------- GUI / Main class -------

class NetworkScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner (with device type)")
        self.root.geometry("1050x700")

        # Top controls
        top_frame = ttk.Frame(root)
        top_frame.pack(fill="x", padx=8, pady=8)

        ttk.Label(top_frame, text="Network (CIDR):").pack(side="left", padx=(0,6))
        self.network_var = tk.StringVar()
        default_net = get_default_local_network() or "192.168.1.0/24"
        self.network_var.set(default_net)
        self.network_entry = ttk.Entry(top_frame, textvariable=self.network_var, width=20)
        self.network_entry.pack(side="left")

        self.scan_btn = ttk.Button(top_frame, text="Scan Network", command=self.start_network_scan)
        self.scan_btn.pack(side="left", padx=6)

        ttk.Label(top_frame, text="Port scan range (e.g. 1-1024) or leave blank = common ports:").pack(side="left", padx=(12,6))
        self.port_range_var = tk.StringVar()
        ttk.Entry(top_frame, textvariable=self.port_range_var, width=18).pack(side="left")

        # Split pane for devices / ports
        main_pane = ttk.PanedWindow(root, orient="horizontal")
        main_pane.pack(fill="both", expand=True, padx=8, pady=8)

        # Left: device tree (now with Type column)
        left_frame = ttk.Frame(main_pane)
        main_pane.add(left_frame, weight=3)

        self.tree = ttk.Treeview(left_frame, columns=("ip","type","mac","hostname"), show="headings", selectmode="browse")
        self.tree.heading("ip", text="IP")
        self.tree.heading("type", text="Type")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("hostname", text="Hostname")
        self.tree.column("ip", width=120)
        self.tree.column("type", width=160)
        self.tree.column("mac", width=180)
        self.tree.column("hostname", width=220)
        self.tree.pack(fill="both", expand=True, side="left")

        scrollbar = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscroll=scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self.on_device_select)

        # Right: port results + actions
        right_frame = ttk.Frame(main_pane)
        main_pane.add(right_frame, weight=2)

        ttk.Label(right_frame, text="Selected device:").pack(anchor="w")
        self.selected_label = ttk.Label(right_frame, text="None")
        self.selected_label.pack(anchor="w", pady=(0,6))

        self.scan_ports_btn = ttk.Button(right_frame, text="Scan Ports", command=self.start_port_scan, state="disabled")
        self.scan_ports_btn.pack(anchor="w", pady=(0,6))

        self.ports_listbox = tk.Listbox(right_frame)
        self.ports_listbox.pack(fill="both", expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status = ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w")
        status.pack(fill="x", side="bottom")

        # Internal state
        self.discovered = {}  # ip -> {ip, mac, hostname, type_label, type_emoji, ttl, ports}
        self.scan_thread = None
        self.port_scan_thread = None

    def set_status(self, text):
        self.status_var.set(text)
        self.root.update_idletasks()

    def start_network_scan(self):
        net_text = self.network_var.get().strip()
        try:
            network = ipaddress.ip_network(net_text, strict=False)
        except Exception as e:
            messagebox.showerror("Invalid network", f"Invalid network CIDR: {e}")
            return
        self.scan_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.discovered.clear()
        self.set_status(f"Scanning {network} ...")
        t = threading.Thread(target=self._scan_network_worker, args=(network,), daemon=True)
        t.start()
        self.scan_thread = t

    def _scan_network_worker(self, network):
        hosts = [str(ip) for ip in network.hosts()]
        reachable = []
        self.set_status(f"Pinging {len(hosts)} hosts ...")
        with ThreadPoolExecutor(max_workers=min(THREAD_WORKERS, len(hosts))) as exe:
            futures = {exe.submit(ping_host, ip): ip for ip in hosts}
            for fut in as_completed(futures):
                ip = futures[fut]
                try:
                    alive = fut.result()
                except Exception:
                    alive = False
                if alive:
                    reachable.append(ip)

        time.sleep(0.2)
        arp = get_arp_table()

        for ip in sorted(reachable, key=lambda x: tuple(map(int,x.split('.')))):
            mac = arp.get(ip, "")
            hostname = resolve_hostname(ip)
            ttl = get_ttl(ip)
            # initial type guess (no ports yet)
            type_label, type_emoji = detect_device_type([], hostname, ttl, mac)
            entry = {"ip": ip, "mac": mac, "hostname": hostname, "type_label": type_label,
                     "type_emoji": type_emoji, "ttl": ttl, "ports": []}
            self.discovered[ip] = entry
            # show "emoji + label" in type column
            type_cell = f"{type_emoji} {type_label}"
            self.tree.insert("", "end", iid=ip, values=(ip, type_cell, mac, hostname))

        self.set_status(f"Scan complete: {len(reachable)} host(s) found")
        self.scan_btn.config(state="normal")

    def on_device_select(self, event):
        sel = self.tree.selection()
        if not sel:
            self.scan_ports_btn.config(state="disabled")
            self.selected_label.config(text="None")
            return
        ip = sel[0]
        self.selected_label.config(text=ip)
        self.scan_ports_btn.config(state="normal")
        self.ports_listbox.delete(0, tk.END)

    def start_port_scan(self):
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        port_range_text = self.port_range_var.get().strip()
        if port_range_text:
            ports_to_scan = []
            if "-" in port_range_text:
                try:
                    a,b = port_range_text.split("-",1)
                    a = int(a.strip()); b = int(b.strip())
                    if a < 1 or b > 65535 or a>b:
                        raise ValueError()
                    ports_to_scan = list(range(a, b+1))
                except Exception:
                    messagebox.showerror("Invalid range", "Port range must be like 1-1024")
                    return
            else:
                try:
                    ports_to_scan = [int(p.strip()) for p in port_range_text.split(",") if p.strip()]
                except Exception:
                    messagebox.showerror("Invalid ports", "Ports must be integers like 22,80,443")
                    return
        else:
            ports_to_scan = COMMON_PORTS

        self.scan_ports_btn.config(state="disabled")
        self.ports_listbox.delete(0, tk.END)
        self.set_status(f"Scanning {len(ports_to_scan)} ports on {ip} ...")
        t = threading.Thread(target=self._port_scan_worker, args=(ip, ports_to_scan), daemon=True)
        t.start()
        self.port_scan_thread = t

    def _port_scan_worker(self, ip, ports):
        open_ports = []
        with ThreadPoolExecutor(max_workers=min(THREAD_WORKERS, len(ports))) as exe:
            futures = {exe.submit(scan_port, ip, p): p for p in ports}
            for fut in as_completed(futures):
                p = futures[fut]
                try:
                    is_open = fut.result()
                except Exception:
                    is_open = False
                if is_open:
                    open_ports.append(p)
                    self.ports_listbox.insert(tk.END, f"Port {p}  (open)")
                    self.ports_listbox.yview_moveto(1.0)

        if not open_ports:
            self.ports_listbox.insert(tk.END, "No open ports found in selection.")

        # update stored ports and re-detect device type with port evidence
        info = self.discovered.get(ip, {})
        info['ports'] = open_ports
        ttl = info.get('ttl')
        hostname = info.get('hostname')
        mac = info.get('mac')
        new_label, new_emoji = detect_device_type(open_ports, hostname, ttl, mac)
        info['type_label'] = new_label
        info['type_emoji'] = new_emoji
        self.discovered[ip] = info

        # update treeview row with new type
        type_cell = f"{new_emoji} {new_label}"
        try:
            # ensure item still exists
            if ip in self.tree.get_children():
                self.tree.item(ip, values=(ip, type_cell, mac, hostname))
        except Exception:
            pass

        self.set_status(f"Port scan complete on {ip}: {len(open_ports)} open")
        self.scan_ports_btn.config(state="normal")

# ------- Main -------

def main():
    root = tk.Tk()
    app = NetworkScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
