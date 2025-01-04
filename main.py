import tkinter as tk
from tkinter import scrolledtext, ttk, messagebox
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading
import time


class NetworkSniffer:
    def __init__(self):
        self.is_running = False

        # Create main window
        self.root = tk.Tk()
        self.root.title("Network Packet Sniffer")
        self.root.geometry("800x600")

        # Create and pack widgets
        self.create_widgets()

    def create_widgets(self):
        # Create control frame
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10)

        # Create interface selection
        ttk.Label(control_frame, text="Interface:").pack(side=tk.LEFT, padx=5)
        self.interface_var = tk.StringVar()
        self.interface_combo = ttk.Combobox(control_frame, textvariable=self.interface_var)
        self.interface_combo['values'] = self.get_interfaces()
        if self.interface_combo['values']:
            self.interface_combo.current(0)
        self.interface_combo.pack(side=tk.LEFT, padx=5)

        # Create buttons
        self.start_button = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_button.pack(side=tk.LEFT, padx=5)

        self.stop_button = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Create clear button
        self.clear_button = ttk.Button(control_frame, text="Clear",
                                       command=lambda: self.output_area.delete(1.0, tk.END))
        self.clear_button.pack(side=tk.LEFT, padx=5)

        # Create output text area
        self.output_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, height=30)
        self.output_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Add status label
        self.status_label = ttk.Label(self.root, text="Status: Ready")
        self.status_label.pack(pady=5)

    def get_interfaces(self):
        """Get list of network interfaces"""
        interfaces = get_working_ifaces()
        return [iface.name for iface in interfaces]

    def packet_callback(self, packet):
        try:
            # Check if packet has IP layer
            if packet.haslayer(IP):
                packet_info = (
                    f'Time: {time.strftime("%H:%M:%S")}\n'
                    f'Source IP: {packet[IP].src}\n'
                    f'Destination IP: {packet[IP].dst}\n'
                    f'Protocol: {packet[IP].proto}\n'
                )

                if packet.haslayer(TCP):
                    packet_info += f'Source Port: {packet[TCP].sport}\n'
                    packet_info += f'Destination Port: {packet[TCP].dport}\n'
                elif packet.haslayer(UDP):
                    packet_info += f'Source Port: {packet[UDP].sport}\n'
                    packet_info += f'Destination Port: {packet[UDP].dport}\n'

                packet_info += f'{"-" * 50}\n'
                self.root.after(0, self.add_to_output, packet_info)
        except Exception as e:
            self.root.after(0, self.add_to_output, f"Error processing packet: {str(e)}\n")

    def start_capture(self):
        if not self.interface_var.get():
            messagebox.showerror("Error", "Please select an interface")
            return

        self.is_running = True
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.status_label.config(text="Status: Capturing...")

        # Start capture in a separate thread
        self.capture_thread = threading.Thread(target=self.capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()

    def stop_capture(self):
        self.is_running = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.status_label.config(text="Status: Stopped")

    def add_to_output(self, text):
        self.output_area.insert(tk.END, text)
        self.output_area.see(tk.END)

    def capture_packets(self):
        try:
            self.add_to_output("Starting packet capture...\n")
            sniff(iface=self.interface_var.get(),
                  prn=self.packet_callback,
                  stop_filter=lambda _: not self.is_running)
        except Exception as e:
            self.root.after(0, self.add_to_output, f"Error: {str(e)}\n")
            self.root.after(0, self.stop_capture)

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    # Initialize Scapy for Windows
    if os.name == 'nt':
        from scapy.arch import get_windows_if_list

    sniffer = NetworkSniffer()
    sniffer.run()
