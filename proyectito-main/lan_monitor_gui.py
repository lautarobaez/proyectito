#!/usr/bin/env python3

import sys
import os
import subprocess
import socket
import sqlite3
import threading
import time
import queue
import csv
from datetime import datetime
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
from config_loader import get, get_int


#cuidado

import configparser
import sqlite3
import tkinter as tk
# … lo que tengas

from config_loader import * 
# cinfig loaderrrrrr .py

DB_FILE = "devices.db"
SCAN_INTERVAL = 60  # segundos predeterminado para scan automático

# ----------------- Utilidades de red -----------------
def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = socket.gethostbyname(socket.gethostname())
    finally:
        s.close()
    return ip

def ip_to_base(ip):
    parts = ip.split('.')
    if len(parts) == 4:
        return '.'.join(parts[:3]) + '.'
    return None

def ping(ip, timeout_ms=400):
    if sys.platform.startswith("win"):
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        # -c 1, timeout in seconds (rounded)
        cmd = ["ping", "-c", "1", "-W", str(max(1, int(timeout_ms/1000))), ip]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

def _looks_like_ip(s):
    try:
        socket.inet_aton(s.strip("()"))
        return True
    except Exception:
        return False

def _looks_like_mac(s):
    s2 = s.replace('-', ':')
    parts = s2.split(':')
    if len(parts) == 6 and all(len(p) == 2 for p in parts):
        return True
    return False

def get_arp_table():
    """Retorna dict ip->mac (o None). Intenta 'arp -a' y 'ip neigh'."""
    table = {}
    try:
        out = subprocess.check_output(["arp", "-a"], stderr=subprocess.DEVNULL, universal_newlines=True)
    except Exception:
        try:
            out = subprocess.check_output(["ip", "neigh"], stderr=subprocess.DEVNULL, universal_newlines=True)
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                ip = parts[0]
                mac = None
                if "lladdr" in parts:
                    mac = parts[parts.index("lladdr") + 1]
                table[ip] = mac
            return table
        except Exception:
            return table
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split()
        ip = None
        mac = None
        for p in parts:
            if _looks_like_ip(p):
                ip = p.strip("()")
            if _looks_like_mac(p):
                mac = p.replace('-', ':')
        if ip:
            table[ip] = mac
    return table

# ----------------- DB -----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        ip TEXT PRIMARY KEY,
        mac TEXT,
        hostname TEXT,
        last_seen TEXT
    )
    """)
    conn.commit()
    conn.close()

def upsert_device(ip, mac, hostname):
    now = datetime.utcnow().isoformat()
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT ip FROM devices WHERE ip = ?", (ip,))
    if cur.fetchone():
        cur.execute("UPDATE devices SET mac = ?, hostname = ?, last_seen = ? WHERE ip = ?",
                    (mac, hostname, now, ip))
    else:
        cur.execute("INSERT INTO devices (ip, mac, hostname, last_seen) VALUES (?, ?, ?, ?)",
                    (ip, mac, hostname, now))
    conn.commit()
    conn.close()

def read_all_devices():
    conn = sqlite3.connect(DB_FILE)
    cur = conn.cursor()
    cur.execute("SELECT ip, mac, hostname, last_seen FROM devices ORDER BY last_seen DESC")
    rows = cur.fetchall()
    conn.close()
    return rows

# ----------------- Scanner en hilo -----------------
def network_scan(base, result_queue, stop_event):
    """
    Escanea base (ej: '192.168.1.') IPs .1..254
    Coloca resultados en result_queue como ('done', None) al terminar
    """
    arp_table = get_arp_table()
    for i in range(1, 255):
        if stop_event.is_set():
            break
        ip = f"{base}{i}"
        alive = ping(ip, timeout_ms=400)
        mac = arp_table.get(ip)
        hostname = None
        if alive:
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = None
            upsert_device(ip, mac, hostname)
            result_queue.put(("found", (ip, mac, hostname)))

        # Opcional: small sleep to avoid saturar la CPU
        time.sleep(0.01)
    result_queue.put(("done", None))

# ----------------- GUI -----------------
class LanMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("LAN Monitor - App de Escritorio")
        self.result_queue = queue.Queue()
        self.scan_thread = None
        self.stop_event = threading.Event()
        self.auto_scan = False
        self.auto_interval = SCAN_INTERVAL

        # UI: top controls
        frm = ttk.Frame(root, padding=8)
        frm.pack(fill="x")
        ttk.Label(frm, text="Subred (/24):").pack(side="left")
        self.subnet_var = tk.StringVar()
        local_ip = get_local_ip()
        base = ip_to_base(local_ip) or "192.168.1."
        self.subnet_var.set(base)
        self.subnet_entry = ttk.Entry(frm, width=15, textvariable=self.subnet_var)
        self.subnet_entry.pack(side="left", padx=4)
        ttk.Button(frm, text="Scan ahora", command=self.scan_now).pack(side="left", padx=4)
        self.auto_btn = ttk.Button(frm, text="Iniciar escaneo automático", command=self.toggle_auto)
        self.auto_btn.pack(side="left", padx=4)
        ttk.Label(frm, text="Intervalo (s):").pack(side="left", padx=(10,0))
        self.interval_var = tk.IntVar(value=self.auto_interval)
        self.interval_entry = ttk.Entry(frm, width=6, textvariable=self.interval_var)
        self.interval_entry.pack(side="left", padx=4)
        ttk.Button(frm, text="Exportar CSV", command=self.export_csv).pack(side="right", padx=4)

        # UI: treeview
        cols = ("ip", "mac", "hostname", "last_seen")
        # nuevo codigo para la tabla - agregue scroll
                # === CONTENEDOR PARA SCROLL ===
        table_frame = tk.Frame(self.root)
        table_frame.pack(fill="both", expand=True, padx=8, pady=8)

        # Scroll vertical
        scroll_y = tk.Scrollbar(table_frame, orient="vertical")
        scroll_y.pack(side="right", fill="y")

        # Scroll horizontal
        scroll_x = tk.Scrollbar(table_frame, orient="horizontal")
        scroll_x.pack(side="bottom", fill="x")

        # Tabla Treeview con scroll
        self.tree = ttk.Treeview(
            table_frame,
            columns=("ip", "hostname", "mac", "last_seen"),
            show="headings",
            yscrollcommand=scroll_y.set,
            xscrollcommand=scroll_x.set
        )

        # Conectar scrollbars
        scroll_y.config(command=self.tree.yview)
        scroll_x.config(command=self.tree.xview)

        # Encabezados
        self.tree.heading("ip", text="IP")
        self.tree.heading("hostname", text="Hostname")
        self.tree.heading("mac", text="MAC")
        self.tree.heading("last_seen", text="Último visto (UTC)")

        # Ancho de columnas
        self.tree.column("ip", width=150)
        self.tree.column("hostname", width=200)
        self.tree.column("mac", width=180)
        self.tree.column("last_seen", width=200)

        self.tree.pack(fill="both", expand=True)


        # status bar
        self.status_var = tk.StringVar(value="Listo")
        status = ttk.Label(root, textvariable=self.status_var, anchor="w")
        status.pack(fill="x", padx=8, pady=(0,8))

        # init
        init_db()
        self.refresh_table()
        # poll queue
        self.root.after(300, self.check_queue)

    def scan_now(self):
        if self.scan_thread and self.scan_thread.is_alive():
            messagebox.showinfo("Escaneo en progreso", "Ya hay un escaneo en curso.")
            return
        base = self.subnet_var.get().strip()
        if not base.endswith('.'):
            messagebox.showerror("Subred inválida", "La subred debe terminar con '.'. Ej: 192.168.1.")
            return
        self.status_var.set("Iniciando escaneo...")
        self.stop_event.clear()
        self.scan_thread = threading.Thread(target=network_scan, args=(base, self.result_queue, self.stop_event), daemon=True)
        self.scan_thread.start()

    def toggle_auto(self):
        if not self.auto_scan:
            try:
                val = int(self.interval_var.get())
                if val < 5:
                    raise ValueError
                self.auto_interval = val
            except Exception:
                messagebox.showerror("Intervalo inválido", "Ingrese un número entero >= 5")
                return
            self.auto_scan = True
            self.auto_btn.config(text="Detener escaneo automático")
            self.status_var.set(f"Escaneo automático cada {self.auto_interval} s")
            self.auto_loop()
        else:
            self.auto_scan = False
            self.auto_btn.config(text="Iniciar escaneo automático")
            self.status_var.set("Escaneo automático detenido")

    def auto_loop(self):
        if not self.auto_scan:
            return
        self.scan_now()

        # programar próxima ejecución tras auto_interval segundos
        self.root.after(self.auto_interval * 1000, self.auto_loop)

    def check_queue(self):
        updated = False
        try:
            while True:
                typ, data = self.result_queue.get_nowait()
                if typ == "found":
                    ip, mac, hostname = data

                    # actualizamos tabla (no releyendola toda)
                    self._upsert_tree_row(ip, mac, hostname)
                    updated = True
                elif typ == "done":
                    self.status_var.set("Escaneo finalizado")
                    updated = True
        except queue.Empty:
            pass
        if updated:
            # opcional: recargar desde DB para sincronizar last_seen
            self.refresh_table()
        self.root.after(300, self.check_queue)

    def _upsert_tree_row(self, ip, mac, hostname):
        # buscar item por ip
        for cid in self.tree.get_children():
            vals = self.tree.item(cid, "values")
            if vals and vals[0] == ip:
                self.tree.item(cid, values=(ip, mac or "-", hostname or "-", datetime.utcnow().isoformat()))
                return
        # si no existe, insert
        self.tree.insert("", 0, values=(ip, mac or "-", hostname or "-", datetime.utcnow().isoformat()))

    def refresh_table(self):
        # recargar desde DB (simple, seguro)
        for cid in self.tree.get_children():
            self.tree.delete(cid)
        rows = read_all_devices()
        for ip, mac, hostname, last in rows:
            self.tree.insert("", "end", values=(ip, mac or "-", hostname or "-", last))

            # cambiar esta funcion 
    def export_csv(self):   # ← FUNCIÓN CORREGIDA
        rows = read_all_devices()
        if not rows:
            messagebox.showinfo("Exportar CSV", "No hay dispositivos para exportar.")
            return

        # Reorganizar columnas en orden claro para Excel
        normalized = []
        for ip, mac, hostname, last in rows:
            normalized.append((ip or "", hostname or "", mac or "", last or ""))

        # Orden natural por IP
        def ip_key(row):
            ip = row[0]
            try:
                parts = [int(p) for p in ip.split('.')]
                while len(parts) < 4:
                    parts.append(0)
                return tuple(parts)
            except Exception:
                return (999, 999, 999, 999, ip)

        normalized.sort(key=ip_key)

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")]
        )
        if not path:
            return

        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                cw = csv.writer(f)
                cw.writerow(["IP", "Hostname", "MAC", "Última Vez Visto (UTC)"])
                for row in normalized:
                    cw.writerow(row)

            messagebox.showinfo("Exportar CSV", f"Exportado correctamente en:\n{path}")

        except Exception as e:
            messagebox.showerror("Error", f"No pude exportar: {e}")

    def on_close(self):
        if messagebox.askokcancel("Salir", "Desea salir?"):
            # detener threads si hay
            self.stop_event.set()
            self.auto_scan = False
            self.root.destroy()

# ----------------- Main -----------------
def main():
    root = tk.Tk()
    app = LanMonitorApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.geometry("720x520")
    root.mainloop()

if __name__ == "__main__":
    main()
