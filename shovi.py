# -------------------------------------------------------------------------
# Shovi
# -------------------------------------------------------------------------
# Description:
#   This tool monitors your clipboard for IP addresses, 
#   then automatically queries Shodan and VirusTotal APIs to retrieve information. 
# 
# Author:
#   uu2
#
# GitHub Repository:
#   https://github.com/ananquay15x9/ShoVi
#
# Date: 12/20/2023
# -------------------------------------------------------------------------

import tkinter as tk
from tkinter import scrolledtext
import pyperclip
import re 
import shodan
import json
import requests
import time
import threading
from threading import Thread
from pprint import pformat

# GUI setup
root = tk.Tk() 
root.title("ShoVi")
root.geometry("500x500")
text = scrolledtext.ScrolledText(root, bg='black', fg='light green', font=("Courier", 10)) 
text.pack(fill=tk.BOTH,expand=True)

# Initial message
text.insert(tk.END, "Please copy an IP address to start.\nWhen IP is not yet selected or is an invalid IP, \nit will show 'null.'\n\n\n")
text.config(state=tk.DISABLED)

#Shodan API Key
SHODAN_API_KEY = 'YOUR-SHODAN-API-KEY' 
VT_API_KEY = 'YOUR-VIRUS-TOTAL-API-KEY'


# Shodan setup
IP_REGEX = r'^(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]?)$'
api = shodan.Shodan(SHODAN_API_KEY)


# All your functions from both scripts
def scan_ip(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
        "x-apikey": VT_API_KEY
    }
    response = requests.get(url, headers=headers)
    return response.json()


def update_text(text_widget, text):
    text_widget.config(state=tk.NORMAL)
    text_widget.insert(tk.END, text + '\n')
    text_widget.config(state=tk.DISABLED)
    # Auto scroll to the end
    text_widget.see(tk.END)
    
    
def get_clipboard():
    return pyperclip.paste()


def is_valid_ip(ip):
    if re.match(IP_REGEX, ip):
        return True
    else: 
        return False
    

def copy_text(event):
    text.clipboard_clear()
    text.clipboard_append(text.selection_get())
text.bind('<Control-Shift-C>', copy_text)

def format_shodan_output(data):
    # Extract relevant fields
    ip = data.get('ip_str')
    os = data.get('os')
    ports = data.get('ports')
    country = data.get('country_name', 'N/A')
    city = data.get('city', 'N/A')
    isp = data.get('isp', 'N/A')
    domains = data.get('domains', 'N/A')
    hostnames = data.get('hostnames', 'N/A')
   
   # Navigate through the nested structure
    cloud_info = data.get('data', [{}])[0].get('cloud', {})
    cloud_provider = cloud_info.get('provider', 'N/A')
    cloud_service = cloud_info.get('service', 'N/A')
   
    # Build output string
    output = f"\nIP: {ip}\n"
    
    if os:
        output += f" OS: {os}\n"
        
    output += f" Country: {country}\n"
    output += f" City: {city}\n"
    output += f" ISP: {isp}\n"
    output += f" Domains: {domains}\n"
    output += f" Hostnames: {hostnames}\n"
    output += f" Cloud Provider: {cloud_provider}\n"
    output += f" Cloud Service: {cloud_service}\n"
        
    if ports:
        output += " Open Ports:\n"
        for p in ports:
            output += f"- {p}\n"
            
    return output

def lookup_ip(ip):
    try:
        result = api.host(ip)
        result = format_shodan_output(result)  # Remove json.loads()
        return result
    except Exception as e:
        return str(e)


last_ip = None
# ...

# Create a stop event
stop_event = threading.Event()

def main(text_widget):
    last_ip = ""
    while not stop_event.is_set():
        clipboard_ip = pyperclip.paste()
        if clipboard_ip != last_ip:
            try:
                # Shodan
                shodan_result = lookup_ip(clipboard_ip)
                update_text(text_widget, shodan_result)
                
                # VirusTotal
                vt_result = scan_ip(clipboard_ip)
                filtered_result = {
                    "IP": vt_result.get("data", {}).get("id"),
                    "Last Analysis Stats": vt_result.get("data", {}).get("attributes", {}).get("last_analysis_stats"),
                }
                update_text(text_widget, json.dumps(filtered_result, indent=5))
                
                last_ip = clipboard_ip
            except Exception as e:
                update_text(text_widget, f"Error: {e}")
        time.sleep(1)

if __name__ == "__main__":
    thread = Thread(target=main, args=(text,))
    thread.start()
    try:
        root.mainloop()
    finally:
        # Set the stop event when the GUI is closed
        stop_event.set()
        # Wait for the worker thread to finish
        thread.join()
