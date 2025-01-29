import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from tkinter import messagebox
import threading
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import os
from datetime import datetime
import time
import json
import csv
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Constants
DEFAULT_TIMEOUT = 10
DEFAULT_HEADERS = {
    'User-Agent': 'URL-Fuzzer/1.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
}

def load_payloads(filename):
    try:
        with open(filename, 'r') as file:
            return [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        messagebox.showerror("Error", f"Payload file {filename} not found!")
        return []

sql_payloads = load_payloads('sql.txt')
xss_payloads = load_payloads('xss.txt')
rce_payloads = load_payloads('rce.txt')
param_pollution_payloads = load_payloads('param_pollution.txt')

def send_request(url, payload, method="GET"):
    try:
        start_time = time.time()
        if method == "GET":
            response = requests.get(
                url + payload,
                timeout=DEFAULT_TIMEOUT,
                headers=DEFAULT_HEADERS,
                verify=False
            )
        elif method == "POST":
            response = requests.post(
                url,
                data=payload,
                timeout=DEFAULT_TIMEOUT,
                headers=DEFAULT_HEADERS,
                verify=False
            )
        elapsed_time = time.time() - start_time
        return response.text, elapsed_time
    except Exception as e:
        return str(e), 0
        return str(e)

def check_vulnerabilities(url, payloads, keyword, progress, max_value):
    results = []
    step = 100 / max_value
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(send_request, url, payload, method_var.get()): payload 
                  for payload in payloads}
        for future in as_completed(futures):
            if not fuzzing_active:
                break
            payload = futures[future]
            try:
                response_text, elapsed_time = future.result()
                if keyword in response_text:
                    results.append(
                        f"Potential vulnerability with payload: {payload} "
                        f"(Response time: {elapsed_time:.2f}s)"
                    )
            except Exception as e:
                results.append(f"Error with payload {payload}: {e}")
            progress['value'] += step
            root.update_idletasks()
    return results

def stop_fuzzing():
    global fuzzing_active
    fuzzing_active = False
    fuzz_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)


def load_custom_payloads():
    global custom_payloads
    file_path = filedialog.askopenfilename(
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if file_path:
        custom_payloads = load_payloads(file_path)
        if custom_payloads:
            messagebox.showinfo("Success", f"Loaded {len(custom_payloads)} custom payloads")
            custom_payload_button.config(text=f"Custom Payloads ({len(custom_payloads)})")

def set_proxy():
    proxy = simpledialog.askstring("Proxy Setup", "Enter proxy (e.g., http://127.0.0.1:8080):")
    if proxy:
        global DEFAULT_HEADERS
        proxies = {
            'http': proxy,
            'https': proxy
        }
        DEFAULT_HEADERS['proxy'] = proxies
        messagebox.showinfo("Success", "Proxy configured successfully!")

def export_results(format_type="txt"):
    if not result_text.get(1.0, tk.END).strip():
        messagebox.showinfo("Info", "No results to export!")
        return
    results_data = result_text.get(1.0, tk.END)
    if format_type == "json":
        file_path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if file_path:
            data = {
                "target_url": url_entry.get(),
                "scan_time": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                "method": method_var.get(),
                "results": results_data
            }
            with open(file_path, 'w') as file:
                json.dump(data, file, indent=4)
            messagebox.showinfo("Success", "Results exported to JSON successfully!")
    elif format_type == "csv":
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if file_path:
            with open(file_path, 'w', newline='') as file:
                writer = csv.writer(file)
                writer.writerow(["URL", "Method", "Vulnerability Type", "Payload", "Response Time"])
                for line in results_data.split('\n'):
                    if line.startswith('[!]'):
                        writer.writerow([url_entry.get(), method_var.get(), "Vulnerability", line])
            messagebox.showinfo("Success", "Results exported to CSV successfully!")
def save_results():
    if not result_text.get(1.0, tk.END).strip():
        messagebox.showinfo("Info", "No results to save!")
        return
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if file_path:
        with open(file_path, 'w') as file:
            file.write(result_text.get(1.0, tk.END))
        messagebox.showinfo("Success", "Results saved successfully!")

def clear_results():
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.config(state=tk.DISABLED)
    progress['value'] = 0

def fuzz_url():
    global fuzzing_active
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a URL")
        return

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url

    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    progress['value'] = 0
    
    fuzzing_active = True
    fuzz_button.config(state=tk.DISABLED)
    stop_button.config(state=tk.NORMAL)

    total_payloads = len(sql_payloads) + len(xss_payloads) + len(rce_payloads) + len(param_pollution_payloads)
    
    threading.Thread(target=run_fuzzing, args=(url, total_payloads)).start()

def run_fuzzing(url, total_payloads):
    sql_results = check_vulnerabilities(url, sql_payloads, "syntax", progress, total_payloads)
    xss_results = check_vulnerabilities(url, xss_payloads, "<script>", progress, total_payloads)
    rce_results = check_vulnerabilities(url, rce_payloads, "uid=", progress, total_payloads)
    param_pollution_results = check_vulnerabilities(url, param_pollution_payloads, "duplicate", progress, total_payloads)

    root.after(0, update_result_text, sql_results, xss_results, rce_results, param_pollution_results)

class TerminalText(tk.Text):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.configure(
            background='black',
            foreground='#00ff00',
            insertbackground='white',
            selectbackground='#333333',
            font=('Courier', 10),
            padx=5,
            pady=5
        )

def update_result_text(sql_results, xss_results, rce_results, param_pollution_results):
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    
    def add_section(title, results):
        result_text.insert(tk.END, f"\n[+] === {title} ===\n", "section")
        if not results:
            result_text.insert(tk.END, f"[-] No {title} vulnerabilities found.\n", "info")
        else:
            for result in results:
                result_text.insert(tk.END, f"[!] {result}\n", "warning")
    
    result_text.tag_configure("section", foreground="#00ffff")
    result_text.tag_configure("info", foreground="#00ff00")
    result_text.tag_configure("warning", foreground="#ff0000")
    
    result_text.insert(tk.END, "=== URL Fuzzer Scan Results ===\n", "section")
    result_text.insert(tk.END, f"[*] Target URL: {url_entry.get()}\n", "info")
    result_text.insert(tk.END, f"[*] Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n", "info")
    
    add_section("SQL Injection", sql_results)
    add_section("Cross-Site Scripting (XSS)", xss_results)
    add_section("Remote Code Execution (RCE)", rce_results)
    add_section("Parameter Pollution", param_pollution_results)
    
    result_text.config(state=tk.DISABLED)
    progress['value'] = 0

# GUI Setup
root = tk.Tk()
root.title("URL Fuzzer")

# Configure the grid to be responsive
root.grid_rowconfigure(2, weight=1)
root.grid_columnconfigure(1, weight=1)

# Add HTTP Method selection
method_frame = ttk.Frame(root)
method_frame.grid(row=0, column=0, columnspan=2, pady=5, sticky="EW")

method_label = ttk.Label(method_frame, text="HTTP Method:")
method_label.grid(row=0, column=0, padx=5)

method_var = tk.StringVar(value="GET")
method_combo = ttk.Combobox(method_frame, textvariable=method_var, values=["GET", "POST", "PUT", "DELETE"])
method_combo.grid(row=0, column=1, padx=5)

# URL Entry
ttk.Label(root, text="Enter URL:").grid(row=1, column=0, padx=10, pady=10, sticky="W")
url_entry = ttk.Entry(root, width=50)
url_entry.grid(row=1, column=1, padx=10, pady=10, sticky="EW")

# Result text with scrollbar (Move this before the buttons)
result_frame = ttk.Frame(root)
result_frame.grid(row=2, column=0, columnspan=2, padx=10, pady=10, sticky="NSEW")
result_frame.grid_rowconfigure(0, weight=1)
result_frame.grid_columnconfigure(0, weight=1)

result_text = TerminalText(result_frame, height=20, width=80)
scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=result_text.yview)
result_text.configure(yscrollcommand=scrollbar.set)

result_text.grid(row=0, column=0, sticky="NSEW")
scrollbar.grid(row=0, column=1, sticky="NS")
result_text.config(state=tk.DISABLED)

# Buttons frame (Move this after result_text creation)
button_frame = ttk.Frame(root)
button_frame.grid(row=3, column=0, columnspan=2, pady=10, sticky="EW")
button_frame.columnconfigure(1, weight=1)

fuzz_button = ttk.Button(button_frame, text="Fuzz URL", command=fuzz_url)
fuzz_button.grid(row=0, column=0, padx=5)

stop_button = ttk.Button(button_frame, text="Stop", command=stop_fuzzing, state=tk.DISABLED)
stop_button.grid(row=0, column=1, padx=5)

# Add export buttons
export_frame = ttk.Frame(button_frame)
export_frame.grid(row=0, column=4, padx=5)

export_json_button = ttk.Button(export_frame, text="Export JSON", 
                              command=lambda: export_results("json"))
export_json_button.grid(row=0, column=0, padx=2)

export_csv_button = ttk.Button(export_frame, text="Export CSV", 
                              command=lambda: export_results("csv"))
export_csv_button.grid(row=0, column=1, padx=2)

# Add custom payload and proxy buttons
custom_payload_button = ttk.Button(button_frame, text="Load Custom Payloads", 
                                 command=load_custom_payloads)
custom_payload_button.grid(row=0, column=5, padx=5)

proxy_button = ttk.Button(button_frame, text="Set Proxy", command=set_proxy)
proxy_button.grid(row=0, column=6, padx=5)

# Progress bar
progress = ttk.Progressbar(root, orient="horizontal", length=400, mode="determinate", 
                          style="green.Horizontal.TProgressbar")
progress.grid(row=4, column=0, columnspan=2, padx=10, pady=10, sticky="EW")

style = ttk.Style(root)
style.configure("green.Horizontal.TProgressbar", troughcolor='white', background='green')

# Initialize global variables
fuzzing_active = False
custom_payloads = []

root.mainloop()