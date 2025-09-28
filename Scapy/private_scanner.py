import socket
import threading
import queue
import subprocess
import re
import platform
from tkinter import *
from tkinter import ttk, simpledialog, messagebox

# GUI + Scanner
root = Tk()
root.title("LAN Network Scanner")
root.geometry("1200x600")

tree = ttk.Treeview(root, columns=("IP", "Hostname", "OS Guess", "Ports"), show="headings")
tree.heading("IP", text="IP Address")
tree.heading("Hostname", text="Hostname")
tree.heading("OS Guess", text="OS Guess")
tree.heading("Ports", text="Open Ports")
tree.pack(fill=BOTH, expand=True)

progress = Label(root, text="")
progress.pack()

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ""

def guess_ttl(ip):
    try:
        if platform.system().lower() == 'windows':
            cmd = ['ping', '-n', '1', ip]
        else:
            cmd = ['ping', '-c', '1', ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=2)
        m = re.search(r'ttl[=|:](\d+)', result.stdout.lower())
        if m:
            return int(m.group(1))
    except:
        pass
    return None

def os_guess_from_ttl(ttl):
    if ttl is None:
        return ""
    if ttl >= 128:
        return "Windows / Network Device?"
    if ttl >= 64:
        return "Linux/Unix?"
    if ttl >= 255:
        return "Cisco/Router?"
    return ""

def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        # send a harmless request for HTTP
        if port == 80:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        data = s.recv(100).decode(errors="ignore")
        s.close()
        return data.strip().replace("\r", "").replace("\n", " ")[:50]
    except:
        return ""

def scan_host(ip, ports_to_check):
    """Return tuple (ip, hostname, osguess, ports string)."""
    hostname = resolve_hostname(ip)
    ttl = guess_ttl(ip)
    osguess = os_guess_from_ttl(ttl)
    openports = []
    for p in ports_to_check:
        try:
            s = socket.socket()
            s.settimeout(0.3)
            s.connect((ip, p))
            banner = grab_banner(ip, p)
            openports.append(f"{p} {banner}")
            s.close()
        except:
            pass
    return (ip, hostname, osguess, ", ".join(openports))

def traceroute(ip):
    system = platform.system().lower()
    if system == 'windows':
        cmd = ['tracert', '-d', '-h', '20', ip]
    else:
        cmd = ['traceroute', '-n', '-m', '20', ip]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        hops = []
        for line in result.stdout.splitlines():
            m = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
            if m:
                hops.append(m.group(1))
        messagebox.showinfo(f"Traceroute to {ip}", "\n".join(hops))
    except Exception as e:
        messagebox.showerror("Error", str(e))

def do_scan():
    subnet = simpledialog.askstring("Subnet", "Enter subnet (e.g. 10.10.1.0/24):")
    if not subnet:
        return
    base, slash = subnet.split('/')
    octets = base.split('.')
    prefix = '.'.join(octets[:3])
    start = 1
    end = 254
    try:
        start_ip = int(octets[3])
    except:
        start_ip = 1
    tree.delete(*tree.get_children())
    progress.config(text="Scanning... please wait")
    root.update()

    ports_to_check = [22, 80, 135, 139, 443, 445]  # common ports
    q = queue.Queue()
    results = []

    def worker():
        while True:
            ip = q.get()
            if ip is None:
                break
            res = scan_host(ip, ports_to_check)
            results.append(res)
            tree.insert("", END, values=res)
            q.task_done()

    threads = []
    for _ in range(50):  # 50 worker threads
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    for i in range(start, end + 1):
        ip = f"{prefix}.{i}"
        q.put(ip)

    q.join()
    for _ in threads:
        q.put(None)
    for t in threads:
        t.join()

    progress.config(text=f"Scan finished. {len(results)} hosts scanned.")

def on_traceroute(event):
    selected = tree.focus()
    if not selected:
        return
    ip = tree.item(selected)['values'][0]
    traceroute(ip)

# Buttons
Button(root, text="Scan Subnet", command=do_scan).pack(pady=5)
Button(root, text="Traceroute Selected Device", command=lambda: on_traceroute(None)).pack(pady=5)

root.mainloop()
