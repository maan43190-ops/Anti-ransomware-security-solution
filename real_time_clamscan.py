import os
import time
import sys
import json
import pyclamd
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from logging.handlers import RotatingFileHandler
import psutil
import threading
import logging
import ctypes
from ctypes import wintypes
import queue

# ==============================
# LOGGING SETUP (APP FOLDER LOGS)
# ==============================

# Get the folder where the script/exe is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Define log file paths inside the same folder
REALTIME_LOG_FILE = os.path.join(BASE_DIR, "clamav_realtime.log")
USB_LOG_FILE = os.path.join(BASE_DIR, "clamav_usb.log")

# Setup format
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

# Realtime logger
realtime_logger = logging.getLogger("RealtimeClam")
realtime_handler = logging.FileHandler(REALTIME_LOG_FILE)
realtime_handler.setFormatter(formatter)
realtime_logger.addHandler(realtime_handler)
realtime_logger.setLevel(logging.INFO)

# USB logger
usb_logger = logging.getLogger("USBClam")
usb_handler = logging.FileHandler(USB_LOG_FILE)
usb_handler.setFormatter(formatter)
usb_logger.addHandler(usb_handler)
usb_logger.setLevel(logging.INFO)
# --- Real-time Logger ---
realtime_logger = logging.getLogger("realtime")
realtime_logger.setLevel(logging.INFO)
rt_handler = RotatingFileHandler(
    REALTIME_LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8"
)
rt_handler.setFormatter(formatter)
realtime_logger.addHandler(rt_handler)

# --- USB Logger ---
usb_logger = logging.getLogger("usb")
usb_logger.setLevel(logging.INFO)
usb_handler = RotatingFileHandler(
    USB_LOG_FILE, maxBytes=5*1024*1024, backupCount=5, encoding="utf-8"
)
usb_handler.setFormatter(formatter)
usb_logger.addHandler(usb_handler)

# ==============================
# WINDOWS DOWNLOAD FOLDER DETECTION
# ==============================
def get_download_folder():
    CSIDL_DOWNLOADS = 0x000C  # Downloads folder
    SHGFP_TYPE_CURRENT = 0
    buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    shell32 = ctypes.windll.shell32
    if shell32.SHGetFolderPathW(None, CSIDL_DOWNLOADS, None, SHGFP_TYPE_CURRENT, buf) == 0:
        return buf.value
    else:
        return os.path.join(os.environ["USERPROFILE"], "Downloads")

# ==============================
# CONFIGURATION
# ==============================
MONITORED_FOLDERS = [
    get_download_folder(),
    os.path.join("D:\\", "transfered from c"),
    os.path.join(os.environ["USERPROFILE"], "Desktop"),
    os.path.join(os.environ["USERPROFILE"], "Downloads"),
    os.path.join(os.environ["USERPROFILE"], "Documents"),
    os.path.join(os.environ["USERPROFILE"], "AppData", "Local", "Temp"),
    os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "WhatsApp"),
    os.path.join(os.environ["USERPROFILE"], "AppData", "Roaming", "Telegram Desktop"),
]

LOG_FILE = os.path.join(os.environ["USERPROFILE"], "clamav_realtime_log.txt")
STARTUP_DELAY = 5
PARTIAL_DOWNLOAD_EXTENSIONS = [".crdownload", ".part", ".tmp", ".download"]


popup_queue = queue.Queue()

# ==============================
# VIRUS SCAN HANDLER
# ==============================
import threading

class ClamAVHandler(FileSystemEventHandler):
    def __init__(self):
        try:
            self.cd = pyclamd.ClamdNetworkSocket()
            self.cd.ping()
            print("[✓] Connected to clamd daemon.")
            realtime_logger.info("Connected to clamd daemon.")
        except Exception as e:
            print(f"[✗] Could not connect to clamd: {e}")
            realtime_logger.error(f"Could not connect to clamd: {e}")
            self.cd = None

        self.last_scanned_files = {}
        self.last_popup_times = {}
        self.popup_cooldown = 60  # seconds
        self.files_in_queue = set()
        self.files_in_queue_lock = threading.Lock()  # Lock added

    def on_created(self, event):
        if not event.is_directory:
            self.scan_and_queue(event.src_path)

    def on_modified(self, event):
        # Ignore modifications to prevent duplicate scans
        pass

    def on_moved(self, event):
        if not event.is_directory:
            self.scan_and_queue(event.dest_path)
            self.last_scanned_files.pop(event.src_path, None)
            self.last_popup_times.pop(event.src_path, None)
            with self.files_in_queue_lock:
                self.files_in_queue.discard(event.src_path)
                self.files_in_queue.discard(event.dest_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.last_scanned_files.pop(event.src_path, None)
            self.last_popup_times.pop(event.src_path, None)
            with self.files_in_queue_lock:
                self.files_in_queue.discard(event.src_path)

    def is_partial_download(self, file_path):
        _, ext = os.path.splitext(file_path)
        return ext.lower() in PARTIAL_DOWNLOAD_EXTENSIONS

    def wait_for_file_complete(self, file_path, timeout=30):
        prev_size = -1
        start_time = time.time()
        while time.time() - start_time < timeout:
            if not os.path.exists(file_path):
                return
            size = os.path.getsize(file_path)
            if size == prev_size:
                return
            prev_size = size
            time.sleep(1)

    def scan_and_queue(self, file_path):
        if not self.cd:
            return
        if not os.path.exists(file_path):
            print(f"[ℹ] Skipped {file_path} (already deleted)")
            realtime_logger.info(f"Skipped {file_path} (already deleted)")
            return
        if self.is_partial_download(file_path):
            return

        try:
            mtime = os.path.getmtime(file_path)
            # Skip if already scanned this version
            if file_path in self.last_scanned_files and self.last_scanned_files[file_path] == mtime:
                return

            self.wait_for_file_complete(file_path)

            # ✅ Double-check existence before scanning
            if not os.path.exists(file_path):
                print(f"[ℹ] File vanished before scan: {file_path}")
                realtime_logger.info(f"File vanished before scan: {file_path}")
                return

            result = self.cd.scan_file(file_path)
            self.last_scanned_files[file_path] = mtime

            if result:
                scan_status = list(result.values())[0][0]
                threat_name = list(result.values())[0][1]

                if scan_status == "FOUND":
                    now = time.time()
                    last_popup = self.last_popup_times.get(file_path, 0)
                    if (now - last_popup > self.popup_cooldown):
                        with self.files_in_queue_lock:
                            if file_path not in self.files_in_queue:
                                popup_queue.put((file_path, result))
                                self.files_in_queue.add(file_path)
                                self.last_popup_times[file_path] = now
                                realtime_logger.warning(f"Queued popup for {file_path}")
                                print(f"[QUEUE] Popup queued for {file_path}")
                            else:
                                print(f"[ℹ] Popup suppressed for {file_path} (already in queue)")
                    else:
                        print(f"[ℹ] Popup suppressed for {file_path} (cooldown)")
                    realtime_logger.warning(f"Threat detected in {file_path}: {result}")
                    print(f"[❗] Threat detected in {file_path}: {result}")
                else:
                    realtime_logger.info(f"Scan info for {file_path}: {result}")
                    print(f"[ℹ] Scan info for {file_path}: {result}")

        except Exception as e:
            print(f"[⚠] Error scanning file {file_path}: {e}")
            realtime_logger.error(f"Error scanning {file_path}: {e}")

# ==============================
# ==============================
# USB DETECTION
# ==============================
def get_usb_drives():
    usb_paths = []
    partitions = psutil.disk_partitions(all=False)
    for p in partitions:
        if 'removable' in p.opts.lower() and os.path.exists(p.mountpoint):
            usb_paths.append(p.mountpoint)
    return usb_paths

# ==============================
# TEMPORARY POPUP (AUTO CLOSE)
# ==============================
def show_temp_popup(title, message, duration=5000):
    popup = tk.Toplevel(root_app)
    popup.title(title)
    popup.geometry("350x120")
    popup.resizable(False, False)

    label = tk.Label(popup, text=message, wraplength=320, justify="center")
    label.pack(expand=True, padx=20, pady=20)

    # Make popup always on top
    popup.attributes("-topmost", True)

    # Close window automatically after `duration` ms
    popup.after(duration, popup.destroy)

def usb_monitor(observer, handler):
    seen_drives = set(get_usb_drives())
    while True:
        current_drives = set(get_usb_drives())
        new_drives = current_drives - seen_drives
        removed_drives = seen_drives - current_drives

        # Handle removed USBs
        for removed in removed_drives:
            print(f"[💽] USB removed: {removed}")
            usb_logger.info(f"USB removed: {removed}")

        # Handle new USBs
        if new_drives:
            for usb in new_drives:
                print(f"[💽] USB inserted: {usb}")
                usb_logger.info(f"USB inserted: {usb}")

                # ✅ Show auto-closing popup when USB inserted
                root_app.after(0, lambda u=usb: show_temp_popup(
                    "USB Inserted",
                    f"USB drive detected at {u}\n\nScanning start, please wait...",
                    duration=5000  # auto-close after 5 sec
                ))

                # Schedule USB for monitoring
                try:
                    observer.schedule(handler, usb, recursive=True)
                    print(f"[👁] Monitoring USB: {usb}")
                    usb_logger.info(f"Monitoring USB: {usb}")
                except Exception as e:
                    usb_logger.error(f"Failed to schedule monitoring for {usb}: {e}")
                    continue  # Skip scanning if scheduling fails

                # 🔍 Scan entire USB in a separate thread
                def scan_usb():
                    threat_found = False
                    print(f"[🔍] Starting full scan of USB: {usb}")
                    usb_logger.info(f"Starting full scan of USB: {usb}")

                    try:
                        for root_dir, dirs, files in os.walk(usb):
                            for file in files:
                                file_path = os.path.join(root_dir, file)
                                if not handler.is_partial_download(file_path):
                                    handler.wait_for_file_complete(file_path)
                                    try:
                                        result = handler.cd.scan_file(file_path)
                                        if result:
                                            scan_status = list(result.values())[0][0]
                                            if scan_status == "FOUND":
                                                threat_found = True
                                                now = time.time()
                                                with handler.files_in_queue_lock:
                                                    if file_path not in handler.files_in_queue:
                                                        popup_queue.put((file_path, result))
                                                        handler.files_in_queue.add(file_path)
                                                        handler.last_popup_times[file_path] = now
                                                        usb_logger.warning(f"Infected file detected on USB insertion: {file_path}")
                                                        print(f"[❗] Infected file detected on USB insertion: {file_path}")
                                    except Exception as e:
                                        usb_logger.error(f"Error scanning file on USB insertion {file_path}: {e}")

                        # ✅ After full scan completes
                        if not threat_found:
                            print(f"[✅] USB scan completed, no threats found: {usb}")
                            usb_logger.info(f"USB scan completed, no threats found: {usb}")
                            root_app.after(0, lambda u=usb: show_temp_popup(
                                "USB Scan Completed",
                                f"No threats found on USB drive: {u}",
                                duration=10000
                            ))
                        else:
                            print(f"[⚠] USB scan completed, threats were found: {usb}")
                            usb_logger.info(f"USB scan completed, threats were found: {usb}")

                    except Exception as e:
                        usb_logger.error(f"Error scanning USB {usb}: {e}")
                        print(f"[⚠] Error scanning USB {usb}: {e}")

                threading.Thread(target=scan_usb, daemon=True).start()

        seen_drives = current_drives
        time.sleep(3)


# ==============================
# SCAN ENTIRE FOLDER
# ==============================
def scan_entire_directory(handler, directory):
    for root_dir, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root_dir, file)
            if not handler.is_partial_download(file_path):
                handler.scan_and_queue(file_path)

# ==============================
# POPUP PROCESSOR
# ==============================
def process_popups(handler):
    try:
        while not popup_queue.empty():
            file_path, result = popup_queue.get()
            try:
                threat_name = list(result.values())[0][1]
            except Exception:
                threat_name = "Unknown Threat"

            realtime_logger.warning(f"Threat Detected: {threat_name} in {file_path}")
            print(f"[❗] Threat Detected: {threat_name} in {file_path}")

            response = messagebox.askyesno(
                "Virus Detected!",
                f"Threat: {threat_name}\nFile: {file_path}\n\nDo you want to DELETE this file?"
            )

            if response:
                try:
                    os.remove(file_path)
                    print("[🗑] File deleted.")
                    realtime_logger.info(f"File deleted: {file_path}")
                    handler.last_scanned_files.pop(file_path, None)
                    handler.last_popup_times.pop(file_path, None)
                except Exception as e:
                    print(f"[⚠] Could not delete file: {e}")
                    realtime_logger.error(f"Could not delete file: {file_path} - {e}")
            else:
                print("[🟡] File kept by user choice.")
                realtime_logger.info(f"File kept by user: {file_path}")
                handler.last_popup_times[file_path] = time.time()

            with handler.files_in_queue_lock:
                handler.files_in_queue.discard(file_path)
                print(f"[QUEUE] Removed {file_path} from files_in_queue")

    except Exception as e:
       realtime_logger.error(f"Error processing popup: {e}")
    finally:
        root_app.after(500, lambda: process_popups(handler))



# ==============================
# MAIN
# ==============================
if __name__ == "__main__":
    time.sleep(STARTUP_DELAY)
    observer = Observer()
    handler = ClamAVHandler()

    # Monitor folders for new files only (no initial full scan)
    for folder in MONITORED_FOLDERS:
        if os.path.exists(folder):
            observer.schedule(handler, folder, recursive=True)
            print(f"[👁] Monitoring: {folder}")
            realtime_logger.info(f"Monitoring: {folder}")

    # Scan and monitor USB drives as before
    for usb in get_usb_drives():
        print(f"[💽] Scanning existing USB: {usb}")
        usb_logger.info(f"Scanning existing USB: {usb}")
        scan_entire_directory(handler, usb)
        observer.schedule(handler, usb, recursive=True)
        print(f"[👁] Monitoring USB: {usb}")
        usb_logger.info(f"Monitoring USB: {usb}")

    threading.Thread(target=usb_monitor, args=(observer, handler), daemon=True).start()

    observer.start()
    print("[✅] Real-time virus scanning started...")
    realtime_logger.info("Real-time virus scanning started...")


    root_app = tk.Tk()
    root_app.withdraw()
    root_app.after(500, lambda: process_popups(handler))
    root_app.mainloop()
