#!/usr/bin/env python3
"""
enhanced_network_scanner.py

Features:
- Auto-detect local subnets (best-effort)
- Ping sweep discovery + ARP/hostname
- Per-host port scans (user range or common)
- Device type heuristics (phone/pc/iot/router)
- Traceroute & ping per-host (show output in popup)
- Topology graph (NetworkX + matplotlib)
- Common vulnerability checks (warnings for risky services; banner grab)
- Safe single-credential test (user supplies one username/password; no brute-force)
- Tkinter GUI, threaded for responsiveness

WARNING: Only scan networks you own or have explicit authorization to scan.
Do NOT run credential tests or any intrusive checks without permission.
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
import os

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, filedialog
except Exception:
    print("Tkinter required. On Linux: sudo apt install python3-tk")
    raise

# Optional visualization libs
try:
    import networkx as nx
    import matplotlib.pyplot as plt
    HAS_NETWORKX = True
except Exception:
    HAS_NETWORKX = False

# ---------------- Config ----------------
PING_TIMEOUT = 1.0
THREAD_WORKERS = 200
COMMON_PORTS = [22, 23, 25, 53, 67, 68, 80, 110, 139, 143, 161, 389, 443, 445, 3306, 3389, 554, 5900, 8080, 8443]
SOCKET_TIMEOUT = 0.6

RISKY_PORTS = {
    23: "Telnet (cleartext - insecure)",
    21: "FTP (consider anonymous or weak creds)",
    445: "SMB (Windows file shares - check access control)",
    3389: "RDP (remote desktop) - ensure strong auth",
    3306: "MySQL - open to network",
    22: "SSH - check version and weak keys",
    554: "RTSP - cameras",
    1883: "MQTT - often insecure for IoT"
}

# ---------------- Utilities ----------------

def run_cmd_capture(args, timeout=5):
    try:
        p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
        return p.stdout + p.stderr
    except Exception as e:
        return str(e)

def get_default_local_networks():
    """
    Try several ways to detect local IPv4 addresses and propose /24 networks.
    Returns list of CIDR strings (deduplicated).
    """
    nets = set()

    # 1) primary outbound IP method
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        nets.add(str(ipaddress.ip_network(local_ip + "/24", strict=False)))
    except Exception:
        pass

    # 2) parse ipconfig / ifconfig / ip addr for additional addresses
    try:
        plat = platform.system().lower()
        if 'windows' in plat:
            out = run_cmd_capture(["ipconfig"], timeout=2)
            for m in re.finditer(r'IPv4 Address[^\d\n]*:\s*([\d\.]+)', out):
                ip = m.group(1)
                nets.add(str(ipaddress.ip_network(ip + "/24", strict=False)))
        else:
            # Linux/macOS
            out = run_cmd_capture(["ip", "addr"], timeout=2)
            for m in re.finditer(r'inet\s+([\d\.]+)/\d+', out):
                ip = m.group(1)
                # skip loopback
                if ip.startswith("127."):
                    continue
                nets.add(str(ipaddress.ip_network(ip + "/24", strict=False)))
            # fallback to ifconfig
            if not nets:
                out = run_cmd_capture(["ifconfig"], timeout=2)
                for m in re.finditer(r'inet\s+([\d\.]+)', out):
                    ip = m.group(1)
                    if ip.startswith("127."):
                        continue
                    nets.add(str(ipaddress.ip_network(ip + "/24", strict=False)))
    except Exception:
        pass

    # filter out private network placeholders if none found, offer default local networks
    if not nets:
        nets.update(["192.168.1.0/24", "10.0.0.0/24", "172.16.0.0/16"])
    return sorted(nets)

def ping_host(ip, timeout=PING_TIMEOUT):
    plat = platform.system().lower()
    if 'windows' in plat:
        args = ["ping", "-n", "1", "-w", str(int(timeout*1000)), str(ip)]
    else:
        args = ["ping", "-c", "1", "-W", str(int(timeout)), str(ip)]
    try:
        res = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def get_ttl(ip):
    """
    Ping and parse TTL (best-effort).
    """
    plat = platform.system().lower()
    try:
        if 'windows' in plat:
            p = subprocess.run(["ping", "-n", "1", "-w", str(int(PING_TIMEOUT*1000)), ip], capture_output=True, text=True, timeout=3)
        else:
            p = subprocess.run(["ping", "-c", "1", "-W", str(int(PING_TIMEOUT)), ip], capture_output=True, text=True, timeout=3)
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
                mac_m = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', line)
                if ip_m and mac_m:
                    ip = ip_m.group(1)
                    mac = mac_m.group(0).replace('-', ':').lower()
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

def grab_banner(ip, port, timeout=1.0, send_bytes=None, use_ssl=False):
    """Try to get a banner (very small and safe)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
        if send_bytes:
            try:
                s.sendall(send_bytes)
            except Exception:
                pass
        try:
            data = s.recv(512)
        except Exception:
            data = b""
        s.close()
        return data.decode(errors='ignore').strip()
    except Exception:
        return ""

# Heuristic device type detection (same as before, slightly extended)
def detect_device_type(open_ports, hostname, ttl, mac):
    h = (hostname or "").lower()
    ports = set(open_ports or [])
    phone_keywords = ["android", "pixel", "galaxy", "iphone", "mobile", "phone"]
    if any(k in h for k in phone_keywords):
        return ("Phone (Android/iOS)", "📱")
    if 5555 in ports:
        return ("Android (ADB)", "🤖")
    if 3389 in ports:
        return ("Windows PC", "🖥️")
    if 22 in ports and 3389 not in ports:
        return ("Linux/Unix", "💻")
    if any(p in ports for p in (554, 8554, 1900, 1883)):
        return ("IoT / Camera", "📷")
    if any(p in ports for p in (23, 2323)):
        return ("IoT / Embedded (telnet)", "🔌")
    if ttl:
        if ttl >= 200:
            return ("Router / Networking Device", "📶")
        if ttl >= 128:
            return ("Windows PC (guess)", "🖥️")
        if ttl >= 64:
            return ("Linux/Unix (guess)", "💻")
    if mac and mac != "" and mac.endswith(":01"):
        return ("Router (MAC hint)", "📶")
    if any(k in h for k in ["router", "gateway", "switch", "ap"]):
        return ("Router", "📶")
    return ("Unknown", "❓")

# ---------------- GUI / Main class ----------------

class EnhancedScanner:
    def __init__(self, root):
        self.root = root
        root.title("Enhanced Network Scanner")
        root.geometry("1100x720")

        # Top: subnet dropdown + scan btn + scan options
        top = ttk.Frame(root); top.pack(fill="x", padx=6, pady=6)
        ttk.Label(top, text="Subnet:").pack(side="left")
        self.subnet_var = tk.StringVar()
        subnets = get_default_local_networks()
        self.subnet_cb = ttk.Combobox(top, textvariable=self.subnet_var, values=subnets, width=22)
        self.subnet_cb.pack(side="left", padx=6)
        self.subnet_var.set(subnets[0])

        self.refresh_if_btn = ttk.Button(top, text="Refresh Subnets", command=self.refresh_subnets)
        self.refresh_if_btn.pack(side="left", padx=6)

        self.scan_btn = ttk.Button(top, text="Scan Network", command=self.start_network_scan)
        self.scan_btn.pack(side="left", padx=6)

        ttk.Label(top, text="Port range:").pack(side="left", padx=(12,4))
        self.port_range_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.port_range_var, width=18).pack(side="left")

        # Middle pane: left tree, right details
        main = ttk.PanedWindow(root, orient="horizontal")
        main.pack(fill="both", expand=True, padx=6, pady=6)

        # Left tree
        left = ttk.Frame(main); main.add(left, weight=3)
        columns = ("ip","type","mac","hostname","ports")
        self.tree = ttk.Treeview(left, columns=columns, show="headings", selectmode="browse")
        for col, txt, w in [("ip","IP",120),("type","Type",140),("mac","MAC",180),("hostname","Hostname",220),("ports","Open ports",150)]:
            self.tree.heading(col, text=txt)
            self.tree.column(col, width=w)
        self.tree.pack(fill="both", expand=True, side="left")
        self.tree.bind("<<TreeviewSelect>>", self.on_select)

        scroll = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview); scroll.pack(side="right", fill="y")
        self.tree.configure(yscroll=scroll.set)

        # Right details
        right = ttk.Frame(main); main.add(right, weight=2)
        ttk.Label(right, text="Selected:").pack(anchor="w")
        self.selected_label = ttk.Label(right, text="None"); self.selected_label.pack(anchor="w", pady=(0,4))

        btn_frame = ttk.Frame(right); btn_frame.pack(fill="x", pady=4)
        self.scan_ports_btn = ttk.Button(btn_frame, text="Scan Ports", command=self.start_port_scan, state="disabled")
        self.scan_ports_btn.pack(side="left", padx=4)
        self.ping_btn = ttk.Button(btn_frame, text="Ping", command=self.run_ping, state="disabled")
        self.ping_btn.pack(side="left", padx=4)
        self.traceroute_btn = ttk.Button(btn_frame, text="Traceroute", command=self.run_traceroute, state="disabled")
        self.traceroute_btn.pack(side="left", padx=4)
        self.check_vuln_btn = ttk.Button(btn_frame, text="Check Vulnerabilities", command=self.run_vuln_checks, state="disabled")
        self.check_vuln_btn.pack(side="left", padx=4)
        self.cred_test_btn = ttk.Button(btn_frame, text="Credential Test (single)", command=self.credential_test, state="disabled")
        self.cred_test_btn.pack(side="left", padx=4)

        ttk.Label(right, text="Port results:").pack(anchor="w", pady=(6,0))
        self.ports_box = tk.Listbox(right, height=12)
        self.ports_box.pack(fill="both", expand=True)

        ttk.Label(right, text="Notes / Warnings:").pack(anchor="w", pady=(6,0))
        self.notes_box = tk.Text(right, height=8, wrap="word")
        self.notes_box.pack(fill="both", expand=True)

        # Bottom: status and topology
        bottom = ttk.Frame(root); bottom.pack(fill="x", padx=6, pady=4)
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status_var, relief="sunken").pack(fill="x")

        # internal state
        self.discovered = {}  # ip -> info dict
        self.scan_thread = None
        self.port_scan_thread = None

    def set_status(self, txt):
        self.status_var.set(txt)
        self.root.update_idletasks()

    def refresh_subnets(self):
        nets = get_default_local_networks()
        self.subnet_cb['values'] = nets
        if nets:
            self.subnet_var.set(nets[0])
        self.set_status("Subnets refreshed")

    def start_network_scan(self):
        net_text = self.subnet_var.get().strip()
        try:
            network = ipaddress.ip_network(net_text, strict=False)
        except Exception as e:
            messagebox.showerror("Invalid network", f"Invalid network CIDR: {e}")
            return
        self.scan_btn.config(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.discovered.clear()
        self.set_status(f"Scanning {network} ...")
        t = threading.Thread(target=self._scan_worker, args=(network,), daemon=True)
        t.start()
        self.scan_thread = t

    def _scan_worker(self, network):
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
        for ip in sorted(reachable, key=lambda x: tuple(map(int, x.split('.')))):
            mac = arp.get(ip, "")
            hostname = resolve_hostname(ip)
            ttl = get_ttl(ip)
            info = {"ip": ip, "mac": mac, "hostname": hostname, "ttl": ttl, "ports": []}
            # initial type guess
            tlabel, temoji = detect_device_type([], hostname, ttl, mac)
            info['type_label'] = tlabel
            info['type_emoji'] = temoji
            self.discovered[ip] = info
            self.tree.insert("", "end", iid=ip, values=(ip, f"{temoji} {tlabel}", mac, hostname, ""))
        self.set_status(f"Scan complete: {len(reachable)} host(s) found")
        self.scan_btn.config(state="normal")

    def on_select(self, event):
        sel = self.tree.selection()
        if not sel:
            self.scan_ports_btn.config(state="disabled")
            self.ping_btn.config(state="disabled")
            self.traceroute_btn.config(state="disabled")
            self.check_vuln_btn.config(state="disabled")
            self.cred_test_btn.config(state="disabled")
            self.selected_label.config(text="None")
            self.ports_box.delete(0, tk.END)
            self.notes_box.delete("1.0", tk.END)
            return
        ip = sel[0]
        info = self.discovered.get(ip, {})
        self.selected_label.config(text=f"{ip}  {info.get('type_emoji','')} {info.get('type_label','')}")
        self.scan_ports_btn.config(state="normal")
        self.ping_btn.config(state="normal")
        self.traceroute_btn.config(state="normal")
        self.check_vuln_btn.config(state="normal")
        self.cred_test_btn.config(state="normal")
        # show previous ports if present
        self.ports_box.delete(0, tk.END)
        for p in info.get('ports', []):
            self.ports_box.insert(tk.END, f"Port {p} (open)")
        self.notes_box.delete("1.0", tk.END)

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
                    a,b = int(a.strip()), int(b.strip())
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
        self.ports_box.delete(0, tk.END)
        self.set_status(f"Scanning {len(ports_to_scan)} ports on {ip} ...")
        t = threading.Thread(target=self._port_worker, args=(ip, ports_to_scan), daemon=True)
        t.start()
        self.port_scan_thread = t

    def _port_worker(self, ip, ports):
        open_ports = []
        banners = {}
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
                    # try banner lightweight (http head for 80/443)
                    if p == 80:
                        b = grab_banner(ip, p, send_bytes=b"HEAD / HTTP/1.0\r\n\r\n")
                    elif p == 443:
                        b = grab_banner(ip, p)  # won't speak TLS here but may get nothing
                    else:
                        b = grab_banner(ip, p)
                    banners[p] = b
                    # update UI progressively
                    self.ports_box.insert(tk.END, f"Port {p}  (open) - {b[:80]}")
                    self.ports_box.yview_moveto(1.0)

        # store and update device type heuristics using discovered ports
        info = self.discovered.get(ip, {})
        info['ports'] = open_ports
        tlabel, temoji = detect_device_type(open_ports, info.get('hostname'), info.get('ttl'), info.get('mac'))
        info['type_label'] = tlabel; info['type_emoji'] = temoji
        self.discovered[ip] = info

        # update tree row
        try:
            if ip in self.tree.get_children():
                self.tree.item(ip, values=(ip, f"{temoji} {tlabel}", info.get('mac',''), info.get('hostname',''), ",".join(map(str,open_ports))))
        except Exception:
            pass

        # store vulnerability notes
        notes = []
        for p in open_ports:
            if p in RISKY_PORTS:
                notes.append(f"[WARNING] {RISKY_PORTS[p]} (port {p} open)")
        # check simple banner clues
        for p,b in banners.items():
            low = (b or "").lower()
            if "openwrt" in low or "dd-wrt" in low or "mikrotik" in low:
                notes.append(f"[INFO] Device firmware hint on port {p}: {b.strip()[:120]}")
            if "apache" in low or "nginx" in low:
                notes.append(f"[INFO] Web server detected on port {p}: {b.strip()[:80]}")

        # update notes box
        self.notes_box.delete("1.0", tk.END)
        if notes:
            self.notes_box.insert(tk.END, "\n".join(notes))
        else:
            self.notes_box.insert(tk.END, "No obvious risky services detected (based on port heuristics).")

        self.set_status(f"Port scan complete on {ip}: {len(open_ports)} open")
        self.scan_ports_btn.config(state="normal")

    def run_ping(self):
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        self.set_status(f"Pinging {ip} ...")
        t = threading.Thread(target=self._ping_worker, args=(ip,), daemon=True)
        t.start()

    def _ping_worker(self, ip):
        out = run_cmd_capture(["ping", "-c" if platform.system().lower()!='windows' else "-n", "4", ip], timeout=8)
        # show in popup
        self._show_text_popup(f"Ping: {ip}", out)

    def run_traceroute(self):
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        self.set_status(f"Traceroute to {ip} ...")
        t = threading.Thread(target=self._traceroute_worker, args=(ip,), daemon=True)
        t.start()

    def _traceroute_worker(self, ip):
        plat = platform.system().lower()
        if 'windows' in plat:
            cmd = ["tracert", "-d", ip]
        else:
            cmd = ["traceroute", "-n", ip]
        out = run_cmd_capture(cmd, timeout=20)
        self._show_text_popup(f"Traceroute: {ip}", out)

    def _show_text_popup(self, title, text):
        def _show():
            w = tk.Toplevel(self.root)
            w.title(title)
            t = tk.Text(w, wrap="none")
            t.insert("1.0", text)
            t.config(state="disabled")
            t.pack(fill="both", expand=True)
            # add scrollbar
            sb = ttk.Scrollbar(w, orient="vertical", command=t.yview); sb.pack(side="right", fill="y")
            t.configure(yscrollcommand=sb.set)
        self.root.after(0, _show)

    def run_vuln_checks(self):
        # currently non-intrusive checks already done after port scan; this will run a quick re-check and show notes
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        info = self.discovered.get(ip, {})
        notes = []
        # Re-evaluate risky ports
        for p in info.get('ports', []):
            if p in RISKY_PORTS:
                notes.append(f"[WARNING] {RISKY_PORTS[p]} (port {p} open)")

        # Additional lightweight probes: check HTTP default page for admin keywords (non intrusive)
        if 80 in info.get('ports', []):
            b = grab_banner(ip, 80, send_bytes=b"GET / HTTP/1.0\r\nHost: \r\n\r\n")
            low = (b or "").lower()
            if any(k in low for k in ["admin", "login", "router", "password"]):
                notes.append("[INFO] HTTP page contains admin/login keywords (check device web admin page)")

        if notes:
            self._show_text_popup(f"Vulnerability quick-check: {ip}", "\n".join(notes))
        else:
            messagebox.showinfo("Vulnerability quick-check", f"No obvious risky services detected on {ip} (non-intrusive).")

    def credential_test(self):
        """
        SAFE single-credential test: user must confirm they have permission.
        We will NOT do brute-force. This prompts for a service and single username/password
        and attempts a simple connection probe depending on service.
        """
        sel = self.tree.selection()
        if not sel:
            return
        ip = sel[0]
        if not messagebox.askyesno("Authorization required", "Do you have explicit authorization to test credentials on this host?"):
            messagebox.showwarning("Not authorized", "Credential testing canceled (requires authorization).")
            return
        # pick a service
        svc = simpledialog.askstring("Service", "Service to test (ssh/http/basic/ftp)?\nEnter one: ssh/http/basic/ftp")
        if not svc:
            return
        user = simpledialog.askstring("Username", "Enter username:")
        if user is None:
            return
        pwd = simpledialog.askstring("Password", "Enter password:", show="*")
        if pwd is None:
            return
        self.set_status(f"Running single credential test for {svc} on {ip} ...")
        t = threading.Thread(target=self._cred_worker, args=(ip, svc.lower(), user, pwd), daemon=True)
        t.start()

    def _cred_worker(self, ip, svc, user, pwd):
        """
        Very small, service-specific single-check implementations.
        No brute-forcing. These attempts may fail depending on service variants.
        """
        result = "Unknown"
        try:
            if svc == "ssh":
                # try to use paramiko if available (but avoid adding as dependency).
                try:
                    import paramiko
                except Exception:
                    self._show_text_popup("Credential test result", "paramiko not installed. Install paramiko to test SSH.")
                    self.set_status("paramiko missing")
                    return
                try:
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip, username=user, password=pwd, timeout=8)
                    client.close()
                    result = "SSH login SUCCESS"
                except Exception as e:
                    result = f"SSH login FAILED: {e}"
            elif svc in ("http","basic"):
                # attempt HTTP Basic auth to root
                import base64, http.client, ssl
                try:
                    conn = http.client.HTTPConnection(ip, timeout=8)
                    auth = base64.b64encode(f"{user}:{pwd}".encode()).decode()
                    conn.request("GET", "/", headers={"Authorization": "Basic " + auth})
                    r = conn.getresponse()
                    result = f"HTTP status: {r.status} {r.reason}"
                except Exception as e:
                    result = f"HTTP test error: {e}"
            elif svc == "ftp":
                try:
                    import ftplib
                    ftp = ftplib.FTP()
                    ftp.connect(ip, 21, timeout=8)
                    ftp.login(user, pwd)
                    ftp.quit()
                    result = "FTP login SUCCESS"
                except Exception as e:
                    result = f"FTP login FAILED: {e}"
            else:
                result = f"Service {svc} not implemented for credential test."
        except Exception as e:
            result = f"Error: {e}"
        self._show_text_popup(f"Credential test result: {ip}", result)
        self.set_status("Credential test done")

    def show_topology(self):
        if not HAS_NETWORKX:
            messagebox.showinfo("Topology", "Install networkx & matplotlib to use topology view.")
            return
        # Build a simple graph: gateway node + discovered hosts
        G = nx.Graph()
        # attempt to set gateway as first .1 in the selected network
        try:
            net = ipaddress.ip_network(self.subnet_var.get(), strict=False)
            gw = str(next(net.hosts()).with_prefixlen).split('/')[0]  # not ideal; we'll assume .1:
            # compute gateway as .1 of network
            net_base = list(net.hosts())
            if net_base:
                gateway = str(list(net.hosts())[0])  # first host
            else:
                gateway = None
        except Exception:
            gateway = None
        if gateway:
            G.add_node(gateway)
        # add hosts and connect to gateway (naive topology)
        for ip, info in self.discovered.items():
            G.add_node(ip)
            if gateway:
                G.add_edge(gateway, ip, weight=1)
        # draw
        plt.figure(figsize=(8,6))
        pos = nx.spring_layout(G)
        nx.draw(G, pos, with_labels=True, node_size=700, font_size=8)
        plt.title("Simple topology (naive: gateway -> hosts)")
        plt.show()

# ---------------- Main entry ----------------

def main():
    root = tk.Tk()
    app = EnhancedScanner(root)
    # add menu/topology
    men = tk.Menu(root)
    root.config(menu=men)
    viewm = tk.Menu(men, tearoff=False)
    men.add_cascade(label="View", menu=viewm)
    viewm.add_command(label="Show Topology Graph", command=app.show_topology)
    root.mainloop()

if __name__ == "__main__":
    main()
