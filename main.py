import logging
from collections import defaultdict
from datetime import datetime
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk
from PIL import Image, ImageTk
from scapy.all import sniff, ICMP, IP
from threading import Thread
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
from matplotlib import style as mplstyle
import requests
import subprocess
import platform

logging.basicConfig(level=logging.INFO, format='%(asctime)s: %(message)s')

mplstyle.use('dark_background')

class WickShieldGUI:
    def __init__(self, master):
        self.master = master
        master.title("Wick Shield - Advanced Network Monitor with IP Blocking")
        self.master.geometry("1280x720")
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.is_closing = False

        self.ip_activity = defaultdict(lambda: defaultdict(int))
        self.suspicious_ip_counts = defaultdict(int)
        self.block_threshold = 10

        self.style = ttk.Style(self.master)
        self.style.theme_use('clam') 
        self.configure_styles()

        self.setup_ui()

        self.sniff_thread = Thread(target=self.sniff_network, daemon=True)
        self.sniff_thread.start()

    def configure_styles(self):
        background_color = '#181B28'
        foreground_color = '#ffffff'
        button_color = '#5c5c5c'
        tab_color = '#444444'

        self.style.configure('TFrame', background=background_color)
        self.style.configure('TButton', background=button_color, foreground=foreground_color, font=('Helvetica', 10), borderwidth=1)
        self.style.map('TButton', background=[('active', tab_color)], foreground=[('active', foreground_color)])
        self.style.configure('TLabel', background=background_color, foreground=foreground_color, font=('Helvetica', 10))
        self.style.configure('TNotebook', background=background_color, borderwidth=0)
        self.style.configure('TNotebook.Tab', background=tab_color, foreground=foreground_color, padding=[5, 2], font=('Helvetica', 10, 'bold'))
        self.style.map('TNotebook.Tab', background=[('selected', button_color)], foreground=[('selected', foreground_color)])
        self.style.configure('TEntry', background=button_color, foreground=foreground_color, highlightthickness=0)

    def setup_ui(self):
        self.load_logo()

        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(expand=True, fill='both')

        self.setup_traffic_tab()
        self.setup_logs_tab()

        self.fetch_ip_btn = ttk.Button(self.master, text="Fetch IP Details", command=self.fetch_ip_details_dialog)
        self.fetch_ip_btn.pack(side=tk.BOTTOM, pady=20)

    def load_logo(self):
        try:
            logo_image = Image.open("wick_shield_logo.png")
            logo_image = logo_image.resize((200, 200), Image.Resampling.LANCZOS)
            self.logo_photo = ImageTk.PhotoImage(logo_image)
            logo_label = tk.Label(self.master, image=self.logo_photo, bg='#181B28')
            logo_label.pack(side=tk.TOP, pady=10)
        except Exception as e:
            logging.error(f"Error loading logo: {e}")


    def setup_traffic_tab(self):
        self.traffic_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.traffic_tab, text="Network Traffic")

        self.fig, self.ax = plt.subplots(figsize=(6, 4), tight_layout=True)
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.traffic_tab)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.ani = FuncAnimation(self.fig, self.update_graph, interval=1000, cache_frame_data=False)

    def setup_logs_tab(self):
        self.logs_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.logs_tab, text="Logs")

        self.log_text = tk.Text(self.logs_tab, state='disabled', wrap='word', background='gray12', foreground='white')
        self.log_text.pack(expand=True, fill='both')

        log_scrollbar = ttk.Scrollbar(self.logs_tab, command=self.log_text.yview, orient='vertical')
        log_scrollbar.pack(side='right', fill='y')
        self.log_text['yscrollcommand'] = log_scrollbar.set

    def sniff_network(self):
        sniff(prn=self.process_packet, filter="icmp", store=0)

    def process_packet(self, packet):
        if packet.haslayer(ICMP):
            src_ip = packet[IP].src
            self.suspicious_ip_counts[src_ip] += 1
            if self.suspicious_ip_counts[src_ip] >= self.block_threshold:
                self.block_ip(src_ip)
            self.ip_activity[src_ip][datetime.now().minute] += 1
            self.log(f"ICMP Packet: {src_ip}")

    def update_graph(self, frame):
        if self.is_closing:
            return
        ips = list(self.ip_activity.keys())
        counts = [sum(self.ip_activity[ip].values()) for ip in ips]
        self.ax.clear()
        self.ax.bar(ips, counts, color='skyblue')
        self.ax.set_xlabel('IP Addresses')
        self.ax.set_ylabel('Packet Count')
        self.ax.set_title('Network Traffic')
        self.canvas.draw()

    def log(self, message):
        self.log_text.config(state='normal')
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.config(state='disabled')
        self.log_text.see(tk.END)

    def block_ip(self, ip):
        """Block the specified IP using system firewall rules."""
        os_type = platform.system()
        try:
            if os_type == "Linux":
                subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True)
            elif os_type == "Windows":
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                "name=\"Block {}\"".format(ip), "dir=in", "action=block", "remoteip={}".format(ip)], check=True)
            logging.info(f"Blocked IP: {ip}")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to block IP {ip}: {e}")

    def fetch_ip_details(self, ip):
        try:
            response = requests.get(f"https://ipinfo.io/{ip}/json")
            details = response.json()
            messagebox.showinfo("IP Details", "\n".join([f"{key}: {value}" for key, value in details.items()]))
        except Exception as e:
            logging.error(f"Failed to fetch IP details: {e}")
            messagebox.showerror("Error", "Failed to fetch IP details.")

    def fetch_ip_details_dialog(self):
        ip = simpledialog.askstring("IP Details", "Enter IP address to fetch details :")
        if ip:
            self.fetch_ip_details(ip)

    def on_closing(self):
        self.is_closing = True
        if self.ani:
            self.ani.event_source.stop() 
        self.master.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    app = WickShieldGUI(root)

    icon_path = "wick_shield_logo.png" 
    try:
        icon_image = Image.open(icon_path)
        icon_photo = ImageTk.PhotoImage(icon_image)
        root.iconphoto(False, icon_photo)
    except Exception as e:
        logging.error(f"Failed to load the icon image: {e}")

    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("Application closed.")
        if not app.is_closing:
            root.destroy()