import tkinter as tk
from tkinter import scrolledtext
from threading import Thread, Event
import scapy.all as scapy

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")
        
        self.create_widgets()
        self.stop_sniffing_event = Event()  # Event to signal stop sniffing
    
    def create_widgets(self):
        # Configure the background color and font for a hacking look
        self.root.configure(bg="black")
        self.root.option_add('*Font', 'Courier 12')

        # Interface input
        self.interface_label = tk.Label(self.root, text="Enter the interface to sniff (e.g., eth0):", fg="green", bg="black")
        self.interface_label.grid(row=0, column=0, padx=10, pady=10, sticky="w")

        self.interface_entry = tk.Entry(self.root, bg="gray", fg="green", font=("Courier", 12))
        self.interface_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Start button
        self.start_button = tk.Button(self.root, text="Start Sniffing", command=self.start_sniffing, fg="black", bg="green", font=("Courier", 12))
        self.start_button.grid(row=1, column=0, padx=10, pady=10)

        # Stop button
        self.stop_button = tk.Button(self.root, text="Stop Sniffing", command=self.stop_sniffing, state="disabled", fg="black", bg="red", font=("Courier", 12))
        self.stop_button.grid(row=1, column=1, padx=10, pady=10)

        # Clear Logs button
        self.clear_button = tk.Button(self.root, text="Clear Logs", command=self.clear_logs, fg="black", bg="yellow", font=("Courier", 12))
        self.clear_button.grid(row=1, column=2, padx=10, pady=10)

        # Output area
        self.output_text = scrolledtext.ScrolledText(self.root, width=80, height=20, bg="black", fg="green", font=("Courier", 12))
        self.output_text.grid(row=2, column=0, columnspan=3, padx=10, pady=10, sticky="nsew")

    def packet_sniffer(self, packet):
        if packet.haslayer(scapy.IP):
            source_ip = packet[scapy.IP].src
            destination_ip = packet[scapy.IP].dst
            protocol = packet[scapy.IP].proto

            output = f"Source IP: {source_ip}\nDestination IP: {destination_ip}\nProtocol: {protocol}\n\n"

            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode(errors='ignore')  # Decode payload if possible
                output += f"Payload: {payload}\n\n"

            self.output_text.insert(tk.END, output)
            self.output_text.see(tk.END)  # Scroll to the end

    def start_sniffing(self):
        interface = self.interface_entry.get().strip()
        self.output_text.delete(1.0, tk.END)  # Clear previous output
        
        self.stop_button.config(state="normal")
        self.start_button.config(state="disabled")
        
        self.stop_sniffing_event.clear()  # Clear the stop event
        
        def sniff_wrapper():
            scapy.sniff(iface=interface, prn=self.packet_sniffer, stop_filter=self.should_stop_sniffing, store=False)

        # Start sniffing in a separate thread
        sniff_thread = Thread(target=sniff_wrapper, daemon=True)
        sniff_thread.start()

    def should_stop_sniffing(self, packet):
        return self.stop_sniffing_event.is_set()  # Return True if stop event is set

    def stop_sniffing(self):
        self.stop_sniffing_event.set()  # Set stop event to stop packet sniffing
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")

    def clear_logs(self):
        self.output_text.delete(1.0, tk.END)  # Clear logs from output area

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
