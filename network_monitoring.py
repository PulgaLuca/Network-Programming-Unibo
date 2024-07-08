"""
STUDENTE: Luca Pulga
MATRICOLA: 0001091461
CORSO: Ingegneria e Scienze Informatiche
DATA: 08/07/2024
"""
import re
import time
import tkinter as tk
from platform import system
from threading import Thread
from tkinter import ttk, messagebox
from subprocess import CalledProcessError, check_output

class NetworkMonitorApp:
    """
    A class to create a Network Monitor Application using Tkinter UI modules.
    
    Attributes:
        root (Tkinter): The main Tkinter window.
        host_entry (Entry): Entry widget for user to input IP addresses he wants to monitor in his network.
        text_area (Text): Text widget to display the status of monitored hosts.
        host_status_list (Listbox): Listbox widget to show the status (online/offline) of hosts (green: online - red: offline).
    """
    def __init__(self, root):
        """
        Initializes the NetworkMonitorApp with the given root window (the main Tkinter).
        
        Parameters:
            root (Tk): The main Tkinter window.
        """
        self.root = root
        self.root.title("Network Monitor with ICMP Ping")
        self.create()

    def create(self) -> None:
        """
        Creates the widgets in the application.
        """
        # Main page builded
        frame = ttk.Frame(self.root, padding="10")
        frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Left panel with the IP monitored second after second.
        left_panel = ttk.Frame(frame)
        left_panel.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        host_label = ttk.Label(left_panel, text="Host IP addresses (comma-separated IPs):")
        host_label.grid(row=0, column=0, sticky=tk.W)
        self.host_entry = ttk.Entry(left_panel, width=50)
        self.host_entry.grid(row=0, column=1, sticky=(tk.W, tk.E))
        start_button = ttk.Button(left_panel, text="Start Monitoring hosts", command=self.start_monitoring)
        start_button.grid(row=1, column=0, columnspan=2)
        self.text_area = tk.Text(left_panel, height=20, width=80)
        self.text_area.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        left_panel.columnconfigure(1, weight=1)
        left_panel.rowconfigure(2, weight=1)
        
        # Right panel with the IP monitored and their relative flags (red: offline host, green: online host).
        right_panel = ttk.Frame(frame)
        right_panel.grid(row=0, column=1, sticky=(tk.N, tk.S, tk.W, tk.E))
        self.host_status_list = tk.Listbox(right_panel, height=20, width=30)
        self.host_status_list.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        scrollbar = ttk.Scrollbar(right_panel, orient=tk.VERTICAL, command=self.host_status_list.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.host_status_list.config(yscrollcommand=scrollbar.set)
        
        right_panel.rowconfigure(0, weight=1)
        right_panel.columnconfigure(0, weight=1)
        
        frame.columnconfigure(0, weight=3)
        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(0, weight=1)
    
    def ping_host(self, host: str) -> str:
        """
        Pings the specified host and returns its status (online/offline).
        
        Parameters:
            host (str): The IP address of the host to ping.
        
        Returns:
            str: 'online' if the host responds to ping, 'offline' if it doesn't respond, 'error' if there is an error during the ping.
        """
        param = '-n' if system().lower() == 'windows' else '-c'
        command = ['ping', param, '1', host]
        try:
            response = check_output(command)
            return 'online'
        except CalledProcessError:
            return 'offline'
        except Exception as e:
            print(f"Error pinging {host}: {e}")
            return 'error'

    def validate_ip(self, ip: str) -> bool:
        """
        Validates an IP address.
        
        Parameters:
            ip (str): The IP address to validate.
        
        Returns:
            bool: True if the IP address is valid, False otherwise.
        """
        ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
        if ip_pattern.match(ip):
            parts = ip.split('.')
            if all(0 <= int(part) <= 255 for part in parts):
                return True
        return False

    def monitor_host(self, host: str) -> None:
        """
        Continuously monitors the specified hosts, updating their status.
        
        Parameters:
            hosts (list): A list of IP addresses to monitor.
        """
        while True:
            status = self.ping_host(host)
            status_text = f"{time.ctime()}: {host} is {status}\n"
            color = 'green' if status == 'online' else 'red'
            self.host_status_list.insert(tk.END, f"{host} - {status}")
            listbox_index = self.host_status_list.size() - 1  # Needed to get the index of the newly inserted IP.
            self.host_status_list.itemconfig(listbox_index, {'bg': color}) # (red: offline host, green: online host)
            self.text_area.insert(tk.END, status_text)
            self.text_area.see(tk.END)
            time.sleep(1)

    def start_monitoring(self) -> None:
        """
        Starts monitoring the hosts entered by the user.
        """
        hosts = self.host_entry.get().split(',')

        if not hosts:
            messagebox.showerror("Error", "Enter valid IP addresses.")
            return

        valid_hosts = [host.strip() for host in hosts if self.validate_ip(host.strip())]
        if not valid_hosts:
            messagebox.showerror("Error", "Enter valid IP addresses.")
            return
        
        invalid_hosts = [host.strip() for host in hosts if not self.validate_ip(host.strip())]
        if invalid_hosts:
            messagebox.showerror("Error", f"Invalid IP addresses: {', '.join(invalid_hosts)}")
            return

        # Managing a 1v1 relation between IPs and Threads.
        for host in valid_hosts:
            monitor_thread = Thread(target=self.monitor_host, args=(host,))
            monitor_thread.daemon = True
            monitor_thread.start()

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkMonitorApp(root)
    root.mainloop()
