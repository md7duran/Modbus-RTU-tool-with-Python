import tkinter as tk
from tkinter import ttk, messagebox
import serial.tools.list_ports
import struct
import time
import threading
from PIL import Image, ImageTk
from pymodbus.client import ModbusSerialClient
from pymodbus.exceptions import ConnectionException, ModbusIOException
import os
import sys

def resource_path(relative_path):
    """Funciona en desarrollo y también cuando está empaquetado con PyInstaller."""
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)
# from PIL import Image, ImageTk # No es necesario si no hay logo

# --- Globals ---
modbus_client = None
scan_thread = None  # Keep track of the scan thread
scan_running = False  # Flag to indicate if scan is running

# Baudrates, Parities, Stop Bits, Byte Sizes for scanning and connection
baudrate_options = [9600, 19200, 38400, 57600, 115200]
parity_options_map = {"None": 'N', "Even": 'E', "Odd": 'O'}
stopbit_options_connect = [1, 1.5, 2] # For main connection
bytesize_options_connect = [7, 8]    # For main connection

stopbit_scan_options = [1, 2]      # For scan iterations
bytesize_scan_options = [7, 8]     # For scan iterations


# ===================== CORE FUNCTIONS =====================

def find_serial_ports():
    """Finds available serial ports."""
    ports = serial.tools.list_ports.comports()
    return [port.device for port in ports]

def refresh_ports_main_window():
    """Refreshes the COM port list in the main window."""
    available_ports = find_serial_ports()
    current_selection = combo_com_main.get()
    combo_com_main['values'] = available_ports
    if available_ports:
        if current_selection in available_ports:
            combo_com_main.set(current_selection)
        else:
            combo_com_main.current(0)
    else:
        combo_com_main.set('')


def open_scan_window():
    """Opens the Modbus network scanning window."""
    global scan_thread, scan_running
    if scan_running:
        messagebox.showwarning("Scanning in Progress", "A scan is already in execution.")
        return

    scan_window = tk.Toplevel(root)
    scan_window.iconbitmap(resource_path("md_app_icon.ico"))
    scan_window.title("Scan Modbus RTU Network")
    scan_window.geometry("850x750") # Adjusted size for new options

    # Prevent closing while scanning
    def on_closing_scan_window():
        if scan_running:
            messagebox.showwarning("Scanning in Progress", "Please wait until scanning is done or stop the scan.")
        else:
            scan_window.destroy()
    scan_window.protocol("WM_DELETE_WINDOW", on_closing_scan_window)

    # --- Configuration Frame ---
    ttk.Label(scan_window, text="Scan Configuration:").pack(pady=5)
    frame_conf_scan = tk.Frame(scan_window)
    frame_conf_scan.pack(pady=5)

    # COM Port for Scan
    tk.Label(frame_conf_scan, text="COM Port:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
    available_scan_ports = find_serial_ports()
    combo_com_scan = ttk.Combobox(frame_conf_scan, values=available_scan_ports, state="readonly", width=10)
    if available_scan_ports:
        combo_com_scan.current(0)
    combo_com_scan.grid(row=0, column=1, padx=5, sticky='w')
    btn_refresh_scan_ports = ttk.Button(frame_conf_scan, text="Refresh", width=8, command=lambda: refresh_ports_scan_window(combo_com_scan))
    btn_refresh_scan_ports.grid(row=0, column=2, padx=5, sticky='w')


    tk.Label(frame_conf_scan, text="Start Slave ID:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
    entry_slave_start = tk.Entry(frame_conf_scan, width=5)
    entry_slave_start.insert(0, "1")
    entry_slave_start.grid(row=1, column=1, padx=5, sticky='w')

    tk.Label(frame_conf_scan, text="End Slave ID:").grid(row=1, column=2, padx=5, pady=2, sticky='w')
    entry_slave_end = tk.Entry(frame_conf_scan, width=5)
    entry_slave_end.insert(0, "32") # Reduced default
    entry_slave_end.grid(row=1, column=3, padx=5, sticky='w')

    tk.Label(frame_conf_scan, text="Timeout (s):").grid(row=2, column=0, padx=5, pady=2, sticky='w')
    entry_timeout_scan = tk.Entry(frame_conf_scan, width=5)
    entry_timeout_scan.insert(0, "0.2")
    entry_timeout_scan.grid(row=2, column=1, padx=5, sticky='w')

    # Baudrates
    tk.Label(frame_conf_scan, text="Baudrates:").grid(row=3, column=0, padx=5, pady=2, sticky='w')
    baud_vars = {}
    for idx, br in enumerate(baudrate_options):
        var = tk.BooleanVar(value=(br == 9600)) # Default 9600 checked
        chk = tk.Checkbutton(frame_conf_scan, text=str(br), variable=var)
        chk.grid(row=3, column=1 + idx, padx=2, pady=2, sticky='w')
        baud_vars[br] = var

    # Parities
    tk.Label(frame_conf_scan, text="Parities:").grid(row=4, column=0, padx=5, pady=2, sticky='w')
    parity_vars = {}
    col_idx = 1
    for name, code in parity_options_map.items():
        var = tk.BooleanVar(value=(code == 'N')) # Default None checked
        chk = tk.Checkbutton(frame_conf_scan, text=name, variable=var)
        chk.grid(row=4, column=col_idx, padx=2, pady=2, sticky='w')
        parity_vars[code] = var
        col_idx += 1

    # Stop Bits for Scan
    tk.Label(frame_conf_scan, text="Stop Bits:").grid(row=5, column=0, padx=5, pady=2, sticky='w')
    stopbit_vars_scan = {}
    for idx, sb in enumerate(stopbit_scan_options):
        var = tk.BooleanVar(value=(sb == 1)) # Default 1 checked
        chk = tk.Checkbutton(frame_conf_scan, text=str(sb), variable=var)
        chk.grid(row=5, column=1 + idx, padx=2, pady=2, sticky='w')
        stopbit_vars_scan[sb] = var

    # Byte Sizes for Scan
    tk.Label(frame_conf_scan, text="Byte Size:").grid(row=6, column=0, padx=5, pady=2, sticky='w')
    bytesize_vars_scan = {}
    for idx, bs in enumerate(bytesize_scan_options):
        var = tk.BooleanVar(value=(bs == 8)) # Default 8 checked
        chk = tk.Checkbutton(frame_conf_scan, text=str(bs), variable=var)
        chk.grid(row=6, column=1 + idx, padx=2, pady=2, sticky='w')
        bytesize_vars_scan[bs] = var


    # --- Results Area ---
    frame_results_scan = tk.Frame(scan_window)
    frame_results_scan.pack(expand=True, fill="both", padx=10, pady=10)

    ttk.Label(frame_results_scan, text="Found Devices:").pack(pady=(5,0), anchor='w')
    tree_scan = ttk.Treeview(frame_results_scan, columns=("Port", "Baudrate", "Parity", "StopBits", "ByteSize", "Slave ID"), show="headings")
    for col in ("Port", "Baudrate", "Parity", "StopBits", "ByteSize", "Slave ID"):
        tree_scan.heading(col, text=col)
        tree_scan.column(col, width=90 if col != "Slave ID" else 60, anchor='center') # Adjusted widths
    tree_scan_scroll = ttk.Scrollbar(frame_results_scan, orient="vertical", command=tree_scan.yview)
    tree_scan.configure(yscrollcommand=tree_scan_scroll.set)
    tree_scan.pack(side="left", expand=True, fill="both")
    tree_scan_scroll.pack(side="right", fill="y")

    # Log
    tk.Label(scan_window, text="Scan Diagnostics:").pack(pady=(10, 0), anchor='w', padx=10)
    log_text_scan = tk.Text(scan_window, height=10, bg="black", fg="lime", font=("Courier", 9), wrap=tk.WORD)
    log_scroll_scan = ttk.Scrollbar(scan_window, orient="vertical", command=log_text_scan.yview)
    log_text_scan.configure(yscrollcommand=log_scroll_scan.set)
    log_text_scan.pack(side="left", expand=True, fill="both", padx=(10,0), pady=5)
    log_scroll_scan.pack(side="right", fill="y", padx=(0,10), pady=5)

    # Progress bar and Status
    progress_scan = ttk.Progressbar(scan_window, mode='indeterminate')
    progress_scan.pack(fill="x", padx=10, pady=(5,0))
    status_label_scan = ttk.Label(scan_window, text="Status: Idle")
    status_label_scan.pack(pady=(0,5), padx=10, anchor='w')

    # --- GUI Update Functions (thread-safe) ---
    def update_log_scan(message):
        if log_text_scan.winfo_exists():
            log_text_scan.insert(tk.END, message + "\n")
            log_text_scan.see(tk.END)

    def update_tree_scan(values):
        if tree_scan.winfo_exists():
            tree_scan.insert("", "end", values=values)

    def update_status_scan(message):
        if status_label_scan.winfo_exists():
            status_label_scan.config(text=f"Status: {message}")

    def refresh_ports_scan_window(combobox_widget):
        """Refreshes the COM port list in the scan window."""
        available_ports = find_serial_ports()
        current_selection = combobox_widget.get()
        combobox_widget['values'] = available_ports
        if available_ports:
            if current_selection in available_ports:
                combobox_widget.set(current_selection)
            else:
                combobox_widget.current(0)
        else:
            combobox_widget.set('')

    # --- Scan Worker Thread ---
    def _scan_worker_thread():
        global scan_running # Use nonlocal for flags modified by parent and this thread
        found_devices_count = 0
        try:
            # --- Get parameters (thread-safe retrieval before loop) ---
            scan_port = combo_com_scan.get() # Get from scan window's combobox
            if not scan_port:
                scan_window.after(0, lambda: messagebox.showerror("Error", "Select a COM port for scanning.", parent=scan_window))
                return

            try:
                slave_id_start = int(entry_slave_start.get())
                slave_id_end = int(entry_slave_end.get())
                timeout_seconds = float(entry_timeout_scan.get())
                if not (1 <= slave_id_start <= slave_id_end <= 247 and timeout_seconds > 0):
                    raise ValueError("Invalid scan parameters.")
            except ValueError as e:
                 scan_window.after(0, lambda: messagebox.showerror("Input Error", f"Verify scan parameters:\n{e}", parent=scan_window))
                 return

            selected_baudrates = [br for br, var in baud_vars.items() if var.get()]
            selected_parities = [code for code, var in parity_vars.items() if var.get()]
            selected_stopbits = [sb for sb, var in stopbit_vars_scan.items() if var.get()]
            selected_bytesizes = [bs for bs, var in bytesize_vars_scan.items() if var.get()]


            if not all([selected_baudrates, selected_parities, selected_stopbits, selected_bytesizes]):
                scan_window.after(0, lambda: messagebox.showwarning("Attention", "You must select at least one option for Baudrate, Parity, Stop Bits, and Byte Size.", parent=scan_window))
                return

            # --- Clear previous results and start UI updates (via 'after') ---
            scan_window.after(0, lambda: tree_scan.delete(*tree_scan.get_children()))
            scan_window.after(0, lambda: log_text_scan.delete("1.0", tk.END))
            scan_window.after(0, update_log_scan, "--- Starting scan ---")
            scan_window.after(0, update_status_scan, f"Scanning {scan_port}...")

            # --- Main Scanning Loop ---
            for baud in selected_baudrates:
                for parity_code in selected_parities:
                    for stopbits_val in selected_stopbits:
                        for bytesize_val in selected_bytesizes:
                            if not scan_running:
                                scan_window.after(0, update_log_scan, "--- Scan interrupted by user ---")
                                return # Exit if scan was stopped

                            parity_name = [n for n, c in parity_options_map.items() if c == parity_code][0]
                            scan_window.after(0, lambda b=baud, p=parity_name, sb=stopbits_val, Bsz=bytesize_val: \
                                update_status_scan(f"Trying {scan_port} @ {b}bps, Parity:{p}, SB:{sb}, BS:{Bsz}"))

                            # Instantiate Modbus client for current parameters
                            current_client = ModbusSerialClient(
                                port=scan_port,
                                baudrate=baud,
                                stopbits=stopbits_val,
                                bytesize=bytesize_val,
                                parity=parity_code,
                                timeout=timeout_seconds,
                                retries=0 # We handle retries/loops externally
                            )

                            try:
                                if not current_client.connect():
                                    scan_window.after(0, update_log_scan,
                                                      f"[{baud} {parity_code} SB:{stopbits_val} BS:{bytesize_val}] ❌ Could not open port {scan_port}")
                                    continue # Try next configuration

                                # Iterate through slave IDs for this config
                                for slave_id in range(slave_id_start, slave_id_end + 1):
                                    if not scan_running:
                                        scan_window.after(0, update_log_scan, "--- Scan interrupted by user ---")
                                        current_client.close()
                                        return

                                    response = None
                                    detected_this_id = False
                                    try:
                                        # Try reading a single holding register (common probe)
                                        response = current_client.read_holding_registers(address=0, count=1, slave=slave_id)
                                        detected_this_id = True # Response received (even if error, but not timeout)
                                        scan_window.after(0, update_log_scan,
                                                          f"[{baud} {parity_code} SB:{stopbits_val} BS:{bytesize_val}] ID {slave_id}: ✅ Response (func 03)")

                                    except ConnectionException as e_conn: # Timeout or no response for this ID
                                        scan_window.after(0, update_log_scan,
                                                          f"[{baud} {parity_code} SB:{stopbits_val} BS:{bytesize_val}] ID {slave_id}: ❌ No response ({e_conn})")
                                    except ModbusIOException as e_modbus_io: # Framing errors, noise, etc.
                                        scan_window.after(0, update_log_scan,
                                                          f"[{baud} {parity_code} SB:{stopbits_val} BS:{bytesize_val}] ID {slave_id}: ⚠️ Modbus IO Error ({e_modbus_io})")
                                        # detected_this_id = True # Optionally consider this a detection
                                    except Exception as e_generic_read:
                                        scan_window.after(0, update_log_scan,
                                                          f"[{baud} {parity_code} SB:{stopbits_val} BS:{bytesize_val}] ID {slave_id}: ⚠️ Unexpected Exception: {e_generic_read}")

                                    if detected_this_id:
                                        found_devices_count += 1
                                        parity_display_name = [name for name, code in parity_options_map.items() if code == parity_code][0]
                                        # Values for tree: Port, Baudrate, Parity, StopBits, ByteSize, Slave ID
                                        tree_values = (scan_port, baud, parity_display_name, stopbits_val, bytesize_val, slave_id)
                                        scan_window.after(0, update_tree_scan, tree_values)

                                    time.sleep(0.01) # Small delay, optional

                            except Exception as e_connect_general:
                                scan_window.after(0, update_log_scan,
                                                  f"[{baud} {parity_code} SB:{stopbits_val} BS:{bytesize_val}] ❌ General error during setup/connect: {str(e_connect_general)}")
                            finally:
                                if current_client.is_socket_open():
                                    current_client.close()
            # --- Scan Finished ---
            scan_window.after(0, update_log_scan, f"--- Scan completed. Devices found: {found_devices_count} ---")
            scan_window.after(0, update_status_scan, "Scan finished.")

            if found_devices_count > 0:
                scan_window.after(0, lambda count=found_devices_count: messagebox.showinfo("Scan Finished", f"Network scan completed.\n\nDevices found: {count}", parent=scan_window))
            else:
                scan_window.after(0, lambda: messagebox.showwarning("No Results", "⚠️ No devices found with the specified range and configurations.\nCheck wiring, parameters, and power.", parent=scan_window))

        except Exception as e_outer: # Catch errors outside the main loop (e.g., parameter conversion before loop)
            scan_window.after(0, update_log_scan, f"--- CRITICAL SCAN ERROR: {e_outer} ---")
            scan_window.after(0, lambda err=e_outer: messagebox.showerror("Error", f"Error in scan: {err}", parent=scan_window))
            scan_window.after(0, update_status_scan, "Error during scan.")
        finally:
            # --- ALWAYS ensure GUI elements are reset ---
            scan_running = False # Crucial to set this flag
            if progress_scan.winfo_exists():
                 scan_window.after(0, progress_scan.stop)
            if start_scan_button.winfo_exists(): # Check if widget still exists
                 scan_window.after(0, lambda: start_scan_button.config(state=tk.NORMAL))
            if stop_scan_button.winfo_exists():
                 scan_window.after(0, lambda: stop_scan_button.config(state=tk.DISABLED))
            # Ensure status reflects end state if not already set
            if status_label_scan.winfo_exists() and \
               "finished" not in status_label_scan.cget("text").lower() and \
               "error" not in status_label_scan.cget("text").lower() and \
               "interrupted" not in status_label_scan.cget("text").lower():
                 scan_window.after(0, lambda: update_status_scan("Idle"))

    def start_scan_action():
        global scan_running, scan_thread # Ensure we're modifying the correct scan_running
        if scan_running: # Should be redundant due to button state, but good check
            return

        # Clear previous results visually before starting progress
        if tree_scan.winfo_exists(): tree_scan.delete(*tree_scan.get_children())
        if log_text_scan.winfo_exists(): log_text_scan.delete("1.0", tk.END)
        if status_label_scan.winfo_exists(): status_label_scan.config(text="Status: Initializing...")

        scan_running = True
        if start_scan_button.winfo_exists(): start_scan_button.config(state=tk.DISABLED)
        if stop_scan_button.winfo_exists(): stop_scan_button.config(state=tk.NORMAL)
        if progress_scan.winfo_exists(): progress_scan.start()

        # Create and start the thread
        scan_thread = threading.Thread(target=_scan_worker_thread, daemon=True)
        scan_thread.start()

    def stop_scan_action():
        global scan_running # To set the flag
        if scan_running:
            scan_running = False # Signal the worker thread to stop
            # Worker thread will handle UI updates on actual stop in its 'finally' or interruption check
            if status_label_scan.winfo_exists(): update_status_scan("Stopping scan...")
            if stop_scan_button.winfo_exists(): stop_scan_button.config(state=tk.DISABLED) # Disable stop, start will re-enable on thread finish
            # Do not re-enable start_scan_button here, let the thread's finally block do it.

    # --- Scan Control Buttons ---
    frame_scan_buttons = tk.Frame(scan_window)
    frame_scan_buttons.pack(pady=10)

    start_scan_button = tk.Button(frame_scan_buttons, text="Start Scan", command=start_scan_action, width=12)
    start_scan_button.pack(side=tk.LEFT, padx=5)

    stop_scan_button = tk.Button(frame_scan_buttons, text="Stop Scan", command=stop_scan_action, state=tk.DISABLED, width=12)
    stop_scan_button.pack(side=tk.LEFT, padx=5)


def open_read_write_window():
    """Opens the window for reading/writing Modbus data."""
    if not modbus_client or not modbus_client.is_socket_open():
        messagebox.showerror("Error", "No active Modbus connection.\nPlease connect from the main window first.")
        return

    rw_window = tk.Toplevel(root)
    rw_window.iconbitmap(resource_path("md_app_icon.ico"))
    rw_window.title("Read/Write Modbus Data")
    rw_window.geometry("750x550")

    # --- Configuration Frame ---
    frame_rw_conf = ttk.LabelFrame(rw_window, text="Read Configuration")
    frame_rw_conf.pack(pady=10, padx=10, fill="x")

    tk.Label(frame_rw_conf, text="Slave ID:").grid(row=0, column=0, padx=5, pady=2, sticky="w")
    entry_slave_rw = tk.Entry(frame_rw_conf, width=5)
    entry_slave_rw.insert(0, "1")
    entry_slave_rw.grid(row=0, column=1, padx=5, pady=2, sticky="w")

    tk.Label(frame_rw_conf, text="Start Address:").grid(row=1, column=0, padx=5, pady=2, sticky="w")
    entry_address_rw = tk.Entry(frame_rw_conf, width=8)
    entry_address_rw.insert(0, "0")
    entry_address_rw.grid(row=1, column=1, padx=5, pady=2, sticky="w")

    tk.Label(frame_rw_conf, text="Quantity:").grid(row=2, column=0, padx=5, pady=2, sticky="w")
    entry_count_rw = tk.Entry(frame_rw_conf, width=5)
    entry_count_rw.insert(0, "10")
    entry_count_rw.grid(row=2, column=1, padx=5, pady=2, sticky="w")

    tk.Label(frame_rw_conf, text="Modbus Function:").grid(row=0, column=2, padx=5, pady=2, sticky="w")
    modbus_functions = ["03 Holding Registers", "04 Input Registers", "01 Coils", "02 Discrete Inputs"]
    combo_function_rw = ttk.Combobox(frame_rw_conf, values=modbus_functions, state="readonly", width=18)
    combo_function_rw.current(0)
    combo_function_rw.grid(row=0, column=3, padx=5, pady=2, sticky="w")

    tk.Label(frame_rw_conf, text="Byte Order (32b):").grid(row=1, column=2, padx=5, pady=2, sticky="w")
    combo_byte_order_rw = ttk.Combobox(frame_rw_conf, values=["Little Endian", "Big Endian"], state="readonly", width=18)
    combo_byte_order_rw.current(0) # Default Little
    combo_byte_order_rw.grid(row=1, column=3, padx=5, pady=2, sticky="w")

    is_zero_based_rw = tk.BooleanVar(value=True)
    chk_zero_based_rw = tk.Checkbutton(frame_rw_conf, text="0-based Address (Modbus Standard)", variable=is_zero_based_rw)
    chk_zero_based_rw.grid(row=2, column=2, columnspan=2, padx=5, pady=2, sticky="w")

    # --- Results Tree ---
    frame_rw_results = ttk.LabelFrame(rw_window, text="Results")
    frame_rw_results.pack(expand=True, fill='both', pady=10, padx=10)

    tree_rw = ttk.Treeview(frame_rw_results, columns=("Address", "Hex", "16-bit", "32-bit", "Float", "ASCII"), show="headings")
    tree_rw.heading("Address", text="Address")
    tree_rw.heading("Hex", text="Hex")
    tree_rw.heading("16-bit", text="Dec (16b)")
    tree_rw.heading("32-bit", text="Dec (32b)")
    tree_rw.heading("Float", text="Float (32b)")
    tree_rw.heading("ASCII", text="ASCII")

    # Adjust column widths
    for col, width in [("Address", 80), ("Hex", 80), ("16-bit", 80), ("32-bit", 100), ("Float", 100), ("ASCII", 100)]:
        tree_rw.column(col, width=width, anchor='center')

    tree_scroll_y_rw = ttk.Scrollbar(frame_rw_results, orient="vertical", command=tree_rw.yview)
    tree_scroll_x_rw = ttk.Scrollbar(frame_rw_results, orient="horizontal", command=tree_rw.xview)
    tree_rw.configure(yscrollcommand=tree_scroll_y_rw.set, xscrollcommand=tree_scroll_x_rw.set)

    tree_scroll_y_rw.pack(side="right", fill="y")
    tree_scroll_x_rw.pack(side="bottom", fill="x")
    tree_rw.pack(expand=True, fill='both')

    lbl_status_rw = tk.Label(rw_window, text="Status: Connected", fg="green", anchor='w')
    lbl_status_rw.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=5)

    def update_rw_status(message, color="gray"):
        if lbl_status_rw.winfo_exists():
            lbl_status_rw.config(text=f"Status: {message}", fg=color)

    def read_modbus_data():
        if not modbus_client or not modbus_client.is_socket_open():
             update_rw_status("Disconnected. Close and reconnect.", "red")
             messagebox.showerror("Error", "Modbus connection lost.", parent=rw_window)
             return

        try:
            if tree_rw.winfo_exists(): tree_rw.delete(*tree_rw.get_children()) # Clear previous results
            slave_id = int(entry_slave_rw.get())
            start_address_input = int(entry_address_rw.get())
            quantity = int(entry_count_rw.get())
            endian_str = combo_byte_order_rw.get()
            function_str = combo_function_rw.get()

            if quantity <= 0:
                messagebox.showwarning("Invalid Input", "Quantity must be greater than 0.", parent=rw_window)
                return

            # Adjust address based on checkbox AFTER validation
            actual_modbus_address = start_address_input
            if not is_zero_based_rw.get(): # If user entered 1-based
                if start_address_input < 1:
                     messagebox.showwarning("Invalid Input", "1-based address must be >= 1.", parent=rw_window)
                     return
                actual_modbus_address = start_address_input - 1 # Convert to 0-based for pymodbus

            if actual_modbus_address < 0: # Should be caught by above if 1-based fails
                 messagebox.showwarning("Invalid Input", "Resulting 0-based address cannot be negative.", parent=rw_window)
                 return

            update_rw_status(f"Reading {quantity} items from ID {slave_id}, Addr {start_address_input} ({'0-based' if is_zero_based_rw.get() else '1-based'})...", "blue")
            rw_window.update_idletasks() # Force GUI update

            response_data = None
            modbus_payload = None
            is_bit_type = False # To differentiate register vs bit processing

            # Determine function code and call appropriate pymodbus method
            if "Holding Registers" in function_str: # FC03
                response_data = modbus_client.read_holding_registers(address=actual_modbus_address, count=quantity, slave=slave_id)
                if response_data and not response_data.isError(): modbus_payload = response_data.registers
            elif "Input Registers" in function_str: # FC04
                response_data = modbus_client.read_input_registers(address=actual_modbus_address, count=quantity, slave=slave_id)
                if response_data and not response_data.isError(): modbus_payload = response_data.registers
            elif "Coils" in function_str: # FC01
                response_data = modbus_client.read_coils(address=actual_modbus_address, count=quantity, slave=slave_id)
                if response_data and not response_data.isError(): modbus_payload = response_data.bits[:quantity]
                is_bit_type = True
            elif "Discrete Inputs" in function_str: # FC02
                response_data = modbus_client.read_discrete_inputs(address=actual_modbus_address, count=quantity, slave=slave_id)
                if response_data and not response_data.isError(): modbus_payload = response_data.bits[:quantity]
                is_bit_type = True
            else:
                 update_rw_status("Invalid Modbus function selected.", "red")
                 return # Should not happen with a readonly combobox

            # --- Process response ---
            if response_data is None or response_data.isError():
                error_message = f"Read failed ({response_data})" if response_data else "Read failed (no response/prior exception)"
                if isinstance(response_data, Exception): # If pymodbus itself returned an exception object
                    error_message = f"Read failed: {response_data}"
                update_rw_status(error_message, "red")
                messagebox.showerror("Read Error", error_message, parent=rw_window)
                return

            update_rw_status(f"Read successful. Displaying {len(modbus_payload)} items.", "green")

            # --- Populate TreeView ---
            struct_endian_format = '<' if endian_str == "Little Endian" else '>' # For struct packing/unpacking

            for i in range(len(modbus_payload)):
                display_address = actual_modbus_address + i
                if not is_zero_based_rw.get():
                    display_address += 1 # Adjust back for display if 1-based was entered

                current_value = modbus_payload[i]
                hex_representation = "-"
                value_16bit = "-"
                value_32bit_int = "-"
                value_32bit_float = "-"
                ascii_representation = "-"

                if is_bit_type:
                    value_16bit = str(current_value) # Display True/False or 1/0
                else: # Register type
                    value_16bit = current_value # Integer value
                    hex_representation = f"{current_value:04X}" # Format as 4-digit hex

                    # Attempt 32-bit and float interpretation (needs next register)
                    if i + 1 < len(modbus_payload):
                        reg1 = modbus_payload[i]   # Current register
                        reg2 = modbus_payload[i+1] # Next register
                        try:
                            # Pack two 16-bit unsigned shorts (H)
                            packed_bytes = struct.pack(f"{struct_endian_format}HH", reg1, reg2)
                            # Unpack as 32-bit unsigned integer (I)
                            value_32bit_int = struct.unpack(f"{struct_endian_format}I", packed_bytes)[0]
                            # Unpack as 32-bit float (f)
                            float_val_raw = struct.unpack(f"{struct_endian_format}f", packed_bytes)[0]

                            if float_val_raw == float('inf') or float_val_raw == float('-inf') or float_val_raw != float_val_raw: # Check for inf/nan
                                value_32bit_float = "N/A"
                            else:
                                value_32bit_float = f"{float_val_raw:.4f}" # Format float
                        except struct.error: # Handle potential struct errors (e.g. bad data)
                             value_32bit_int = "StructErr"
                             value_32bit_float = "StructErr"
                        except Exception:
                             value_32bit_int = "ConvErr"
                             value_32bit_float = "ConvErr"


                    # Attempt ASCII interpretation (split 16-bit register into two bytes)
                    try:
                        # Order of bytes for ASCII might depend on device/convention (High byte first or Low byte first)
                        # Assuming High byte then Low byte for display.
                        byte_high = (current_value >> 8) & 0xFF
                        byte_low = current_value & 0xFF
                        chars = ""
                        for byte_val in [byte_high, byte_low]: # Common order: MSB, LSB
                            if 32 <= byte_val <= 126: # Printable ASCII
                                chars += chr(byte_val)
                            else:
                                chars += '.' # Placeholder for non-printable
                        ascii_representation = chars
                    except Exception:
                        ascii_representation = "??"

                # Insert row into the tree
                tree_rw.insert("", "end", values=(
                    display_address,
                    hex_representation,
                    value_16bit,
                    value_32bit_int,
                    value_32bit_float,
                    ascii_representation
                ))

        except ConnectionException as e:
             update_rw_status(f"Connection error: {e}", "red")
             messagebox.showerror("Connection Error", str(e), parent=rw_window)
        except ValueError as e: # For int() or float() conversion errors on input fields
             update_rw_status("Error in input parameters.", "red")
             messagebox.showerror("Input Error", f"Verify numeric inputs:\n{e}", parent=rw_window)
        except Exception as e: # Catch-all for other unexpected errors
            update_rw_status(f"Unexpected error: {e}", "red")
            messagebox.showerror("Error", f"An unexpected error occurred during read:\n{str(e)}", parent=rw_window)

    # Read Button
    tk.Button(rw_window, text="Read Data", command=read_modbus_data).pack(side=tk.BOTTOM, pady=10)


# ===================== MAIN CONNECTION FUNCTIONS =====================

def connect_modbus():
    """Establishes the main Modbus connection."""
    global modbus_client
    if modbus_client and modbus_client.is_socket_open():
        messagebox.showinfo("Information", "A connection is already active.")
        # Optionally offer to disconnect first or just open the window
        open_read_write_window()
        return

    port = combo_com_main.get()
    baudrate_str = combo_baud_main.get()
    parity_str = combo_parity_main.get()
    stopbits_val_str = combo_stopbits_main.get()
    bytesize_val_str = combo_bytesize_main.get()


    if not port:
        messagebox.showerror("Error", "Select a COM port.")
        return
    if not all([baudrate_str, parity_str, stopbits_val_str, bytesize_val_str]):
         messagebox.showerror("Error", "Ensure Baudrate, Parity, Stop Bits, and Byte Size are selected.")
         return

    try:
        baudrate = int(baudrate_str)
        parity_code = parity_options_map[parity_str]
        stopbits_val = float(stopbits_val_str) # float for 1.5
        bytesize_val = int(bytesize_val_str)


        # Close previous connection if any (shouldn't be needed if logic is correct, but safe)
        if modbus_client and modbus_client.is_socket_open():
            modbus_client.close()

        status_bar_main.config(text=f"Status: Connecting to {port} ({baudrate}, {parity_str}, SB:{stopbits_val}, BS:{bytesize_val})...", fg="orange")
        root.update_idletasks() # Force GUI to update status message

        modbus_client = ModbusSerialClient(
            port=port,
            baudrate=baudrate,
            stopbits=stopbits_val,
            bytesize=bytesize_val,
            parity=parity_code,
            timeout=1 # Standard timeout for connection attempt
        )

        if modbus_client.connect():
            status_bar_main.config(text=f"Status: Connected to {port} ({baudrate}, {parity_str}, SB:{stopbits_val}, BS:{bytesize_val})", fg="green")
            messagebox.showinfo("Connected", f"Successfully connected to {port}.")
            open_read_write_window() # Open the read/write window
        else:
            status_bar_main.config(text="Status: Connection failed", fg="red")
            messagebox.showerror("Error", f"Could not connect to {port} with the selected configuration.\nVerify device and parameters.")
            modbus_client = None # Clear client on failure
    except ValueError: # Catches int()/float() conversion errors for baud/stopbits/bytesize
         status_bar_main.config(text="Status: Parameter error", fg="red")
         messagebox.showerror("Error", "Invalid Baudrate, Stop Bits, or Byte Size format.")
    except Exception as e:
        status_bar_main.config(text=f"Status: Error - {e}", fg="red")
        messagebox.showerror("Error", f"Unexpected error during connection:\n{e}")
        modbus_client = None


def disconnect_modbus():
     """Closes the main Modbus connection."""
     global modbus_client
     if modbus_client and modbus_client.is_socket_open():
         modbus_client.close()
         status_bar_main.config(text="Status: Disconnected", fg="gray")
         messagebox.showinfo("Disconnected", "Modbus connection closed.")
     else:
         messagebox.showinfo("Information", "No active connection to close.")
     modbus_client = None # Ensure client is cleared


# ===================== MAIN GUI SETUP =====================

root = tk.Tk()
# --- Logo de la empresa ---
try:
    logo_img = Image.open(resource_path("md_logo_banner.png"))  # Cambia el nombre si es necesario
    logo_img = logo_img.resize((120, 60), Image.Resampling.LANCZOS)  # Ajusta el tamaño si lo ves necesario
    logo_tk = ImageTk.PhotoImage(logo_img)

    logo_label = tk.Label(root, image=logo_tk)
    logo_label.image = logo_tk  # Previene que Python borre la imagen
    logo_label.pack(pady=(10, 0))  # Ajusta el padding si es necesario
except Exception as e:
    print(f"No se pudo cargar el logo: {e}")

root.iconbitmap(resource_path("md_app_icon.ico"))
root.title("Modbus RTU Tool - PyModbus")
root.geometry("480x360") # Adjusted size for new controls + caption

# --- Connection Configuration Frame (Main Window) ---
conf_frame_main = ttk.LabelFrame(root, text="Connection Configuration")
conf_frame_main.pack(pady=10, padx=10, fill="x")

# Row 0: COM Port
tk.Label(conf_frame_main, text="COM Port:").grid(row=0, column=0, padx=5, pady=5, sticky="w")
initial_ports = find_serial_ports()
combo_com_main = ttk.Combobox(conf_frame_main, values=initial_ports, state="readonly", width=15)
combo_com_main.grid(row=0, column=1, padx=5, pady=5, sticky="ew")
if initial_ports:
    combo_com_main.current(0)
btn_refresh_main = ttk.Button(conf_frame_main, text="Refresh", command=refresh_ports_main_window, width=8)
btn_refresh_main.grid(row=0, column=2, padx=5, pady=5)


# Row 1: Baudrate
tk.Label(conf_frame_main, text="Baudrate:").grid(row=1, column=0, padx=5, pady=5, sticky="w")
combo_baud_main = ttk.Combobox(conf_frame_main, values=baudrate_options, state="readonly", width=15)
combo_baud_main.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
combo_baud_main.set(9600) # Default

# Row 2: Parity
tk.Label(conf_frame_main, text="Parity:").grid(row=2, column=0, padx=5, pady=5, sticky="w")
parity_display_options = list(parity_options_map.keys())
combo_parity_main = ttk.Combobox(conf_frame_main, values=parity_display_options, state="readonly", width=15)
combo_parity_main.grid(row=2, column=1, padx=5, pady=5, sticky="ew")
combo_parity_main.current(0) # Default "None"

# Row 3: Stop Bits
tk.Label(conf_frame_main, text="Stop Bits:").grid(row=3, column=0, padx=5, pady=5, sticky="w")
combo_stopbits_main = ttk.Combobox(conf_frame_main, values=stopbit_options_connect, state="readonly", width=15)
combo_stopbits_main.grid(row=3, column=1, padx=5, pady=5, sticky="ew")
combo_stopbits_main.set(1) # Default

# Row 4: Byte Size
tk.Label(conf_frame_main, text="Byte Size:").grid(row=4, column=0, padx=5, pady=5, sticky="w")
combo_bytesize_main = ttk.Combobox(conf_frame_main, values=bytesize_options_connect, state="readonly", width=15)
combo_bytesize_main.grid(row=4, column=1, padx=5, pady=5, sticky="ew")
combo_bytesize_main.set(8) # Default

conf_frame_main.columnconfigure(1, weight=1) # Make comboboxes expand

# --- Action Buttons Frame (Main Window) ---
button_frame_main = tk.Frame(root)
button_frame_main.pack(pady=10, fill="x", padx=10)

btn_connect_main = tk.Button(button_frame_main, text="Connect & Read/Write", command=connect_modbus)
btn_connect_main.pack(side=tk.LEFT, expand=True, padx=5)

btn_disconnect_main = tk.Button(button_frame_main, text="Disconnect", command=disconnect_modbus)
btn_disconnect_main.pack(side=tk.LEFT, expand=True, padx=5)

btn_scan_main = tk.Button(button_frame_main, text="Scan Network", command=open_scan_window)
btn_scan_main.pack(side=tk.LEFT, expand=True, padx=5)


# --- Status Bar (Main Window) ---
# Pack status bar first, then caption below it
status_bar_main = tk.Label(root, text="Status: Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W, fg="gray")
status_bar_main.pack(side=tk.BOTTOM, fill=tk.X, pady=(0, 2)) # Add tiny padding below status bar

# --- Caption Wrapper aligned to the right ---
frame_caption = tk.Frame(root)
frame_caption.pack(side=tk.BOTTOM, fill='x')  # Lo pone en la parte inferior

caption_label = tk.Label(frame_caption, text="MD",
                         font=("TkDefaultFont", 7), fg="dim gray", anchor='e')
caption_label.pack(side=tk.RIGHT, padx=10, pady=(0, 5))  # Lo alinea a la derecha




# Gracefully close connection on main window exit
def on_main_window_close():
    global scan_running # Check if scan is active
    if scan_running:
         messagebox.showwarning("Scan in Progress", "A network scan is still running in the background.\nPlease stop it or wait for it to finish before closing.")
         # For now, just warn. A more robust solution might involve signalling the scan thread to stop.
         # However, since scan_thread is a daemon, it will exit if the main program exits.
         # The main issue is user awareness and potential unsaved scan results (if any were being saved).
    if modbus_client and modbus_client.is_socket_open():
        modbus_client.close()
    root.destroy()

root.protocol("WM_DELETE_WINDOW", on_main_window_close)
root.mainloop()