"""
advanced_hotspot_attendance.py

Multi-technique Hotspot/WiFi Attendance system (Windows)
- Register user devices (Name, MAC, SSID)
- Scan network using: ping sweep, SSDP probe, ARP table, nbtstat lookups
- Mark Present only if registered MAC found in ARP results
- ✅ Remove member button added
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import csv, os, subprocess, re, socket, ipaddress, threading, time
import uuid
import sys

DEVICE_DB = "registered_devices.csv"
PING_TIMEOUT_MS = 200
THREAD_LIMIT = 200


# ----------------- Utility: persistence -----------------

def load_registered_devices():
    if not os.path.exists(DEVICE_DB):
        return []
    with open(DEVICE_DB, newline='', encoding='utf-8') as f:
        return list(csv.DictReader(f))


def save_registered_device(name, mac, ssid):
    file_exists = os.path.exists(DEVICE_DB)
    with open(DEVICE_DB, "a", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(["Name", "MAC", "SSID"])
        writer.writerow([name, mac.lower(), ssid])


def export_attendance_log(rows):
    path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
    if not path:
        return
    with open(path, "w", newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(["Name", "MAC", "SSID", "Status", "Timestamp"])
        for r in rows:
            writer.writerow(r)
    return path


# ----------------- Network helpers -----------------

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = None
    finally:
        s.close()
    return ip


def run_cmd(cmd, timeout=6):
    try:
        return subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:
        return ""


def ping_once(ip):
    subprocess.call(f"ping -n 1 -w {PING_TIMEOUT_MS} {ip}",
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def arp_table_macs():
    out = run_cmd("arp -a")
    macs = re.findall(r"([0-9a-fA-F]{2}(?:-[0-9a-fA-F]{2}){5})", out)
    return {m.lower() for m in macs}


def nbtstat_query(ip):
    run_cmd(f"nbtstat -A {ip}", timeout=3)


def try_netbios_all(ips):
    for ip in ips:
        try:
            nbtstat_query(ip)
        except:
            pass


def ssdp_probe():
    msg = "\r\n".join([
        'M-SEARCH * HTTP/1.1',
        'HOST: 239.255.255.250:1900',
        'MAN: "ssdp:discover"',
        'MX: 3',
        'ST: ssdp:all',
        '', ''
    ]).encode('utf-8')
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(2)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.sendto(msg, ("239.255.255.250", 1900))
        try:
            while True:
                data, addr = sock.recvfrom(2048)
        except socket.timeout:
            pass
        sock.close()
    except Exception:
        pass


def fast_subnet_ping(slogger, on_progress=None):
    local_ip = get_local_ip()
    if not local_ip:
        slogger("Could not determine local IP. Connect to network/hotspot first.")
        return []
    net = ipaddress.ip_network(local_ip + "/24", strict=False)
    ips = [str(ip) for ip in net.hosts()]
    slogger(f"Local IP: {local_ip}  Subnet: {net.with_prefixlen}  Hosts: {len(ips)}")
    threads = []
    for i, ip in enumerate(ips):
        t = threading.Thread(target=ping_once, args=(ip,), daemon=True)
        threads.append(t)
    for i in range(0, len(threads), THREAD_LIMIT):
        batch = threads[i:i + THREAD_LIMIT]
        for t in batch:
            t.start()
        for t in batch:
            t.join()
        if on_progress:
            on_progress(min(100, int((i + THREAD_LIMIT) / len(threads) * 100)))
    slogger("Ping sweep completed.")
    return ips


# ----------------- Core scanning routine -----------------

def full_discovery(slogger, progress_callback=None):
    slogger("Starting discovery sequence...")
    initial_arp = arp_table_macs()
    slogger(f"Initial ARP MACs: {len(initial_arp)}")

    slogger("Sending SSDP multicast probe...")
    ssdp_thread = threading.Thread(target=ssdp_probe, daemon=True)
    ssdp_thread.start()

    slogger("Starting ping sweep (this may take ~15-60s depending on network).")
    ips = fast_subnet_ping(slogger, on_progress=progress_callback)

    time.sleep(1.0)
    slogger("Running NetBIOS queries (nbtstat) on discovered IPs...")

    arp_out = run_cmd("arp -a")
    ip_list = re.findall(r"(\d+\.\d+\.\d+\.\d+)\s+[-0-9a-fA-F]+\s+[a-zA-Z0-9]+", arp_out)
    if not ip_list:
        try:
            local_ip = get_local_ip()
            net = ipaddress.ip_network(local_ip + "/24", strict=False)
            ip_list = [str(ip) for i, ip in enumerate(net.hosts()) if i < 64]
        except Exception:
            ip_list = []

    nb_threads = []
    for ip in ip_list:
        t = threading.Thread(target=nbtstat_query, args=(ip,), daemon=True)
        nb_threads.append(t)
    for t in nb_threads:
        t.start()
    for t in nb_threads:
        t.join(timeout=0.12)

    time.sleep(0.5)
    final_arp = arp_table_macs()
    slogger(f"Final ARP MACs: {len(final_arp)}")

    ssdp_thread.join(timeout=0.1)

    return final_arp


# ----------------- Tkinter UI -----------------

class AttendanceApp:
    def __init__(self, root):
        self.root = root
        root.title("Advanced Hotspot/WiFi Attendance")
        root.geometry("900x600")

        # Top registration frame
        top = ttk.LabelFrame(root, text="Register Device (one-time)")
        top.pack(fill="x", padx=8, pady=6)

        ttk.Label(top, text="User Name:").grid(row=0, column=0, padx=6, pady=4, sticky="w")
        self.name_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.name_var, width=30).grid(row=0, column=1, padx=6, pady=4)

        ttk.Label(top, text="Device MAC:").grid(row=1, column=0, padx=6, pady=4, sticky="w")
        self.mac_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.mac_var, width=30).grid(row=1, column=1, padx=6, pady=4)
        ttk.Label(top, text="Format: aa-bb-cc-dd-ee-ff").grid(row=1, column=2, padx=6)

        ttk.Label(top, text="SSID (optional):").grid(row=2, column=0, padx=6, pady=4, sticky="w")
        self.ssid_var = tk.StringVar()
        ttk.Entry(top, textvariable=self.ssid_var, width=30).grid(row=2, column=1, padx=6, pady=4)

        ttk.Button(top, text="Register Device", command=self.register_device).grid(row=3, column=0, columnspan=2,
                                                                                   pady=8)

        # Control buttons
        ctrl = ttk.Frame(root)
        ctrl.pack(fill="x", padx=8, pady=4)
        ttk.Button(ctrl, text="Scan & Mark Attendance", command=self.start_scan).pack(side="left", padx=6)
        ttk.Button(ctrl, text="Export Registered CSV", command=self.export_registered).pack(side="left", padx=6)
        ttk.Button(ctrl, text="Export Attendance Log", command=self.export_log).pack(side="left", padx=6)

        # ✅ NEW Remove Member button
        ttk.Button(ctrl, text="Remove Member", command=self.remove_member).pack(side="left", padx=6)

        self.progress = ttk.Progressbar(ctrl, length=300)
        self.progress.pack(side="right", padx=10)

        # Attendance table
        left_frame = ttk.LabelFrame(root, text="Attendance (Latest Session)")
        left_frame.pack(fill="both", expand=True, side="left", padx=8, pady=6)

        cols = ("Name", "MAC", "SSID", "Status")
        self.tree = ttk.Treeview(left_frame, columns=cols, show="headings", height=18)
        for c in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=160)
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)

        # Debug log
        right_frame = ttk.LabelFrame(root, text="Debug Log")
        right_frame.pack(fill="both", expand=True, side="right", padx=8, pady=6)

        self.log = scrolledtext.ScrolledText(right_frame, wrap="word", width=60, height=20, state="normal")
        self.log.pack(fill="both", expand=True, padx=4, pady=4)

        self.attendance_rows = []

    def slog(self, txt):
        ts = time.strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {txt}\n")
        self.log.see("end")

    def register_device(self):
        name = self.name_var.get().strip()
        mac = self.mac_var.get().strip().lower()
        ssid = self.ssid_var.get().strip()
        if not name or not mac:
            messagebox.showwarning("Missing fields", "Please enter Name and MAC.")
            return
        cleaned = re.sub(r"[^0-9a-fA-F]", "", mac)
        if len(cleaned) != 12:
            messagebox.showwarning("MAC format", "MAC must be 12 hex characters.")
            return
        mac_norm = "-".join([cleaned[i:i + 2] for i in range(0, 12, 2)]).lower()
        save_registered_device(name, mac_norm, ssid)
        self.slog(f"Registered: {name} / {mac_norm} / {ssid}")
        messagebox.showinfo("Registered", f"{name} registered with MAC {mac_norm}")
        self.name_var.set("");
        self.mac_var.set("");
        self.ssid_var.set("")

    def remove_member(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Select Member", "Please select a member to remove.")
            return

        item = self.tree.item(selected[0])
        name, mac, ssid, _ = item["values"]

        if messagebox.askyesno("Confirm Delete", f"Remove {name} ({mac})?"):
            rows = load_registered_devices()
            rows = [r for r in rows if r["MAC"].lower() != mac.lower()]

            with open(DEVICE_DB, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Name", "MAC", "SSID"])
                for r in rows:
                    w.writerow([r["Name"], r["MAC"], r.get("SSID", "")])

            self.tree.delete(selected[0])
            self.slog(f"Removed: {name} / {mac}")
            messagebox.showinfo("Deleted", f"{name} removed successfully.")

    def export_registered(self):
        regs = load_registered_devices()
        if not regs:
            messagebox.showinfo("No data", "No registered devices to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not path:
            return
        with open(path, "w", newline='', encoding='utf-8') as f:
            w = csv.writer(f)
            w.writerow(["Name", "MAC", "SSID"])
            for r in regs:
                w.writerow([r["Name"], r["MAC"], r["SSID"]])
        messagebox.showinfo("Saved", f"Saved to {path}")

    def export_log(self):
        if not self.attendance_rows:
            messagebox.showinfo("No data", "No attendance scanned yet.")
            return
        p = export_attendance_log(self.attendance_rows)
        if p:
            messagebox.showinfo("Saved", f"Attendance log saved to:\n{p}")

    def start_scan(self):
        t = threading.Thread(target=self.run_scan_thread, daemon=True)
        t.start()

    def run_scan_thread(self):
        self.progress["value"] = 0
        self.slog("==== Starting attendance scan ====")

        def progress_cb(p):
            try:
                self.progress["value"] = int(p)
            except:
                pass

        try:
            found_macs = full_discovery(self.slog, progress_callback=progress_cb)
            regs = load_registered_devices()
            self.attendance_rows = []
            self.tree.delete(*self.tree.get_children())
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            for r in regs:
                mac = r["MAC"].lower()
                status = "✅ Present" if mac in found_macs else "❌ Absent"
                self.tree.insert("", "end", values=(r["Name"], mac, r.get("SSID", ""), status))
                self.attendance_rows.append((r["Name"], mac, r.get("SSID", ""), status, timestamp))
            self.slog("Attendance marking complete.")
            messagebox.showinfo("Scan Complete", "Attendance scan complete.")
        except Exception as e:
            self.slog(f"Error: {e}")
            messagebox.showerror("Error", f"Scan failed: {e}")
        finally:
            self.progress["value"] = 0


# ----------------- Run -----------------

def main():
    root = tk.Tk()
    app = AttendanceApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
