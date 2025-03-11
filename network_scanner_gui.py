#!/usr/bin/env python3
import scapy.all as scapy
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime  # For dynamic year


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return [{"ip": response[1].psrc, "mac": response[1].hwsrc} for response in answered_list]


def on_scan():
    target_ip = ip_entry.get()
    if not target_ip:
        messagebox.showerror("Error", "Please enter an IP range to scan.")
        return

    try:
        results = scan(target_ip)
        result_text.config(state=tk.NORMAL)
        result_text.delete(1.0, tk.END)

        if results:
            result_text.insert(tk.END, " Discovered Devices\n", 'header')
            result_text.insert(tk.END, "----------------------------------------\n", 'divider')
            result_text.insert(tk.END, " IP Address\t\tMAC Address\n", 'subheader')
            result_text.insert(tk.END, "----------------------------------------\n", 'divider')
            for client in results:
                result_text.insert(tk.END, f" {client['ip']}\t{client['mac']}\n")
        else:
            result_text.insert(tk.END, "\n No devices found\n", 'error')

        result_text.config(state=tk.DISABLED)
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred: {str(e)}")


root = tk.Tk()
root.title("Network Scanner Pro")
root.geometry("600x500")
root.configure(bg='#f0f0f0')

style = ttk.Style()
style.theme_use('clam')
style.configure('TButton', font=('Helvetica', 10, 'bold'), padding=6)
style.configure('TLabel', background='#f0f0f0', font=('Helvetica', 9))
style.configure('TEntry', font=('Helvetica', 10))

logo_frame = tk.Frame(root, bg='#f0f0f0')
logo_frame.pack(pady=10)

logo_label = tk.Label(logo_frame, text="🌐", font=('Helvetica', 40), bg='#f0f0f0', fg='#2980b9')
logo_label.pack(side=tk.LEFT)

header_text = tk.Label(logo_frame,
                       text="Network Scanner Pro\nDiscover Connected Devices",
                       font=('Helvetica', 14, 'bold'),
                       bg='#f0f0f0',
                       fg='#2c3e50')
header_text.pack(side=tk.LEFT, padx=10)

# Input Frame
input_frame = tk.Frame(root, bg='#f0f0f0')
input_frame.pack(pady=15)

ip_label = ttk.Label(input_frame, text="Enter IP Range to Scan:")
ip_label.pack(side=tk.LEFT, padx=5)

ip_entry = ttk.Entry(input_frame, width=30)
ip_entry.pack(side=tk.LEFT, padx=5)
ip_entry.insert(0, "Example: 192.168.1.0/24")

scan_button = ttk.Button(input_frame, text="Start Scan", command=on_scan)
scan_button.pack(side=tk.LEFT, padx=10)

# Results Frame
results_frame = tk.Frame(root)
results_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

result_text = tk.Text(results_frame,
                      wrap=tk.WORD,
                      height=15,
                      width=70,
                      font=('Consolas', 9),
                      bg='#ffffff',
                      fg='#2c3e50',
                      padx=10,
                      pady=10,
                      state=tk.DISABLED)

result_text.tag_configure('header', font=('Helvetica', 12, 'bold'), foreground='#2980b9')
result_text.tag_configure('subheader', font=('Helvetica', 10, 'bold'))
result_text.tag_configure('divider', foreground='#7f8c8d')
result_text.tag_configure('error', foreground='#e74c3c', justify=tk.CENTER)

scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=result_text.yview)
result_text.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

current_year = datetime.now().year
footer_text = f"© {current_year} Network Scanner Pro | By Hazim Aiman | For authorized use only"
footer = tk.Label(root,
                  text=footer_text,
                  font=('Helvetica', 8),
                  bg='#f0f0f0',
                  fg='#7f8c8d')
footer.pack(side=tk.BOTTOM, pady=5)

root.mainloop()
