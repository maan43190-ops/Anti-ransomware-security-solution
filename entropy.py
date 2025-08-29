import time
import os
import math
import psutil
import tkinter as tk
from tkinter import messagebox
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import win32api
import win32file
import win32process
import collections
import json
import logging   # ✅ added

# Get the folder where the script/exe is located
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_FILE = os.path.join(BASE_DIR, "entropy_monitor.log")

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

logger = logging.getLogger(__name__)

def safe_delete(file_path, retries=5, delay=1):
    """Try deleting a file multiple times if it's locked, with proper logs."""
    for attempt in range(retries):
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
                logging.info(f"[🗑] File deleted: {file_path}")
            return True
        except Exception as e:
            logging.warning(f"[!] Could not delete {file_path} (attempt {attempt+1}/{retries}): {e}")
            time.sleep(delay)
    return False
# ---------------- CONFIG ----------------
MONITORED_EXTENSIONS = ['.txt', '.docx', '.pdf', '.xls', '.xlsx', '.csv', '.log', '.json']
SUSPICIOUS_EXTENSIONS = [
    '.encrypted', '.locked', '.pay', '.crypted', '.locky', '.wannacry', '.crypt', '.payday',
    '.crypz', '.zepto', '.odin', '.cerber', '.cryptowall', '.petya', '.phobos', '.bip', '.banjo', '.ccc'
]
# ✅ SAFE extensions that can appear normally (don’t auto-flag unless entropy high in user folder)
SAFE_EXTENSIONS = [
    '.enc', '.dat', '.bin', '.pak', '.idx', '.db', '.sqlite',
    '.cab', '.res', '.dll', '.sys', '.ini', '.cfg', '.conf', '.json',
    '.log', '.key'
]

ENTROPY_THRESHOLD = 7.3
SAFE_PROCESSES = ['excel.exe', 'libreoffice.exe', 'winword.exe', 'acrord32.exe', 'powerpnt.exe']
PROCESS_EVENT_WINDOW = 20  # seconds
PROCESS_FILE_THRESHOLD = 5
ENTROPY_JUMP_THRESHOLD = 1.0
PERSIST_FILE = "entropy_monitor_state.json"
# ----------------------------------------
# 🚫 Excluded paths (system folders)
EXCLUDED_PATHS = [
    r"C:\Windows",
    r"C:\Program Files",
    r"C:\Program Files (x86)",
    r"C:\$RECYCLE.BIN",
    r"D:\$RECYCLE.BIN", 
    r"E:\$RECYCLE.BIN", 
    r"F:\$RECYCLE.BIN",
    r"C:\Users\Dell\AppData\Local\Microsoft\OneDrive\logs", 
]

# ✅ User folders (where ransomware usually encrypts data)
USER_FOLDERS = [
    os.path.expanduser("~/Documents"),
    os.path.expanduser("~/Desktop"),
    os.path.expanduser("~/Downloads"),
]
USER_FOLDERS = [os.path.normpath(p).lower() for p in USER_FOLDERS]

# ----------------------------------------

recent_events = collections.defaultdict(list)  # PID -> [timestamps]
file_entropy_cache = {}  # file_path -> last_entropy
def terminate_process_tree(pid):
    try:
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)
        for child in children:
            child.terminate()
        parent.terminate()
        logging.info(f"[💀] Process tree {pid} terminated!")
    except Exception as e:
        logging.warning(f"[!] Error terminating process tree {pid}: {e}")

def is_excluded(file_path):
    """Return True if file should be excluded (system/recycle/hidden)."""
    norm_path = os.path.normpath(file_path)
    lower_path = norm_path.lower()

    # 🚫 1. Skip system folders
    for path in EXCLUDED_PATHS:
        if lower_path.startswith(os.path.normpath(path).lower()):
            return True

    # 🚫 2. Skip any drive's recycle bin (C:\$Recycle.Bin, D:\$Recycle.Bin, etc.)
    if f"{os.sep}$recycle.bin{os.sep}" in lower_path:
        return True

    # 🚫 3. Skip hidden/system files (Windows attributes)
    try:
        import ctypes
        attrs = ctypes.windll.kernel32.GetFileAttributesW(file_path)
        if attrs != -1:
            # FILE_ATTRIBUTE_HIDDEN = 0x2, FILE_ATTRIBUTE_SYSTEM = 0x4
            if attrs & 0x2 or attrs & 0x4:
                return True
    except Exception:
        pass

    return False

# ---------- Persistence Functions ----------
def load_state():
    global file_entropy_cache, recent_events
    if os.path.exists(PERSIST_FILE):
        try:
            with open(PERSIST_FILE, "r") as f:
                data = json.load(f)
                file_entropy_cache = data.get("entropy_cache", {})
                recent_events_data = data.get("recent_events", {})
                recent_events = collections.defaultdict(list, {
                    int(pid): times for pid, times in recent_events_data.items()
                })
            logging.info(f"[✓] State loaded from {PERSIST_FILE}")
        except Exception as e:
            logging.warning(f"[!] Failed to load state: {e}")

def save_state():
    try:
        with open(PERSIST_FILE, "w") as f:
            json.dump({
                "entropy_cache": file_entropy_cache,
                "recent_events": {str(pid): times for pid, times in recent_events.items()}
            }, f)
        logging.info(f"[✓] State saved to {PERSIST_FILE}")
    except Exception as e:
        logging.warning(f"[!] Failed to save state: {e}")


def calculate_entropy(file_path, chunk_size=8*1024):
    try:
        size = os.path.getsize(file_path)
        if size == 0:
            return 0.0

        with open(file_path, "rb") as f:
            # Always read from start
            start_data = f.read(chunk_size)

            # If big enough, also sample from end
            if size > chunk_size:
                f.seek(-chunk_size, os.SEEK_END)
                end_data = f.read(chunk_size)
            else:
                end_data = b""

        data = start_data + end_data
        if not data:
            return 0.0

        from collections import Counter
        counter = Counter(data)
        total = len(data)
        entropy = -sum(
            count / total * math.log2(count / total)
            for count in counter.values()
        )

        logging.info(f"[INFO] [📊] Entropy for {file_path}: {entropy:.2f}")
        return entropy

    except PermissionError:
        logging.warning(f"[WARNING] [⚠] Permission denied reading {file_path}")
        return 0.0
    except Exception as e:
        logging.warning(f"[!] Error calculating entropy for {file_path}: {e}")
        return 0.0


def is_monitored_file(file_path):
    _, ext = os.path.splitext(file_path)
    return ext.lower() in MONITORED_EXTENSIONS  # ✅ force lowercase

def is_suspicious_extension(file_path):
    _, ext = os.path.splitext(file_path)
    return ext.lower() in SUSPICIOUS_EXTENSIONS  # ✅ force lowercase

def should_flag(file_path, entropy, pid):
    _, ext = os.path.splitext(file_path)
    ext = ext.lower()  # ✅ normalize

    # 🚩 Immediate hard flag if suspicious extension
    if ext in SUSPICIOUS_EXTENSIONS:
        logging.warning(f"[WARNING] [⚠] Immediate flag for suspicious extension: {ext} ({file_path})")
        return True

    # ⚠️ Safe extensions → only flag if high entropy + in user folder
    if ext in SAFE_EXTENSIONS:
        if entropy > ENTROPY_THRESHOLD:
            norm_path = os.path.normpath(file_path).lower()
            if any(norm_path.startswith(folder) for folder in USER_FOLDERS):
                logging.warning(f"[WARNING] [⚠] High entropy file in safe extension ({ext}): {file_path}")
                return True
        return False

    # 📄 Normal monitored files → check entropy
    if not is_monitored_file(file_path):
        return False
    if entropy <= ENTROPY_THRESHOLD:
        return False

    # ✅ Skip safe processes (Word, Excel, etc.)
    pname = None
    try:
        pname = psutil.Process(pid).name() if pid else None
    except:
        pass
    if pname and pname.lower() in SAFE_PROCESSES:
        logging.info(f"[INFO] [✅] Skipping safe process {pname} (PID: {pid})")
        return False

    # --- Entropy / cache logic ---
    last_entropy = file_entropy_cache.get(file_path)

    # 🔥 Always flag if new OR entropy is above threshold
    if last_entropy is None or entropy > ENTROPY_THRESHOLD:
        file_entropy_cache[file_path] = entropy
        logging.warning(f"[WARNING] [⚠] New/high entropy file detected: {file_path} (Entropy: {entropy:.2f})")
        return True

    # Update cache
    file_entropy_cache[file_path] = entropy

    # Check for significant entropy jump
    if entropy - last_entropy >= ENTROPY_JUMP_THRESHOLD:
        now = time.time()
        if pid:
            recent_events[pid].append(now)
            recent_events[pid] = [t for t in recent_events[pid] if now - t <= PROCESS_EVENT_WINDOW]
            if len(recent_events[pid]) >= PROCESS_FILE_THRESHOLD:
                logging.warning(f"[WARNING] [⚠] Entropy spike detected in process PID {pid} ({pname}) for {file_path}")
                return True
        else:
            logging.warning(f"[WARNING] [⚠] Entropy spike detected in {file_path}")
            return True

    return False

class EntropyMonitorHandler(FileSystemEventHandler):
    suspended_pids = set()  # ✅ class-level attribute

    def __init__(self):
        super().__init__()
          # Track timestamps of suspicious files per PID
        self.suspicious_activity = collections.defaultdict(list)
    def on_created(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.check_file(event.src_path)

    def find_process_by_file(self, file_path):
    #Try exact handle match; if none, fall back to matching the folder in cmdline/CWD.
     norm = os.path.normpath(file_path)

    # 1) Exact open handle (best, but may miss very short writes)
     for proc in psutil.process_iter(['pid', 'name']):
        try:
            for f in proc.open_files():
                if os.path.normpath(f.path) == norm:
                    return proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # 2) Fallback: match directory in cmdline or cwd
     folder = os.path.dirname(norm).lower()
     for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cwd']):
        try:
            cmd = ' '.join(proc.info.get('cmdline') or []).lower()
            cwd = (proc.info.get('cwd') or '').lower()
            if folder and (folder in cmd or folder == cwd):
                return proc.pid
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

     return None

    def check_file(self, file_path):
        if not os.path.exists(file_path) or is_excluded(file_path):
            return

        ext = os.path.splitext(file_path)[1].lower()
        entropy = calculate_entropy(file_path)

        # Reset entropy cache for this file
        file_entropy_cache.pop(file_path, None)

        if entropy > ENTROPY_THRESHOLD or is_suspicious_extension(file_path):
            logger.info(f"[+] Checked {file_path} - Entropy: {entropy:.2f}")

        # Safe file → skip further checks
        if ext in SAFE_EXTENSIONS and entropy <= ENTROPY_THRESHOLD:
            return

        pid = self.find_process_by_file(file_path)

        # Always try to flag suspicious files
        if should_flag(file_path, entropy, pid):
            try:
                if pid:
                    proc = psutil.Process(pid)
                    try:
                        proc_name = proc.name().lower()
                    except Exception:
                        proc_name = "unknown"

                    logger.warning(f"[⚠] Suspected process {proc_name} (PID: {pid}) using file...")

                    # ✅ Suspend process first
                    try:
                        proc.suspend()
                        logger.info(f"[⏸] Process {proc_name} (PID: {pid}) suspended.")
                    except Exception as e:
                        logger.error(f"[!] Failed to suspend process {pid}: {e}")

                    # 🔹 Show popup to ask user
                    root = tk.Tk()
                    root.withdraw()
                    result = messagebox.askyesno(
                        "High Entropy Alert!",
                        f"Suspicious file detected:\n{file_path}\n\n"
                        f"Process: {proc_name} (PID: {pid}) is using this file.\n\n"
                        f"Do you want to TERMINATE the process and DELETE the file?"
                    )

                    if result:  # User chose YES
                        terminate_process_tree(pid)
                        logger.info(f"[💀] Process tree {pid} terminated!")
                        safe_delete(file_path)
                        logger.info(f"[🗑] File deleted: {file_path}")
                    else:  # User chose NO
                        try:
                            proc.resume()
                            logger.info(f"[↩] Process {proc_name} (PID: {pid}) resumed (user allowed).")
                        except Exception as e:
                            logger.error(f"[!] Failed to resume process {pid}: {e}")

                else:
                    # No PID found → still delete the file
                    for attempt in range(5):
                        if safe_delete(file_path):
                            logger.info(f"[🗑] File deleted: {file_path}")
                            break
                        time.sleep(0.5)
                    else:
                        logger.error(f"[!] Could not delete {file_path} (no PID found).")

                # Clear cache and save state
                file_entropy_cache.pop(file_path, None)
                save_state()

            except Exception as e:
                logger.error(f"[❌] Failed to mitigate file {file_path}: {e}")


    def show_process_popup(self, proc, first_file):
     pid = proc.pid
     try:
        pname = proc.name()
     except Exception:
        pname = "unknown"

     root = tk.Tk()
     root.withdraw()
     root.after(10, root.destroy)  # ✅ cleanup hidden window

    # ✅ Suspend process first
     try:
        proc.suspend()
        logger.info(f"[⏸] Process {pname} (PID: {pid}) suspended.")
        self.suspended_pids.add(pid)
     except Exception as e:
        logger.error(f"[!] Failed to suspend process {pid}: {e}")

     msg = (f"Suspicious process detected:\n\n"
           f"Process: {pname} (PID: {pid})\n"
           f"First flagged file: {first_file}\n\n"
           f"Do you want to TERMINATE this process and DELETE all suspicious files it created?\n"
           f"(Click 'No' to RESUME process)")

     result = messagebox.askyesno("High Entropy Alert!", msg)

     if result:  # ✅ User chose TERMINATE
        try:
            terminate_process_tree(pid)
            logger.warning(f"[💀] Process tree {pid} terminated.")

            # Delete only files flagged for this PID
            for fpath, ent in list(file_entropy_cache.items()):
                creator_pid = self.find_process_by_file(fpath)
                if creator_pid == pid and os.path.exists(fpath):
                    if safe_delete(fpath):
                        logger.info(f"[🗑] Deleted file created by PID {pid}: {fpath}")
                    file_entropy_cache.pop(fpath, None)

            self.suspended_pids.discard(pid)
        except Exception as e:
            logger.error(f"[!] Failed to terminate process {pid}: {e}")

     else:  # ❌ User chose RESUME
        try:
            proc.resume()
            logger.info(f"[↩] Process {pname} (PID: {pid}) resumed (user allowed).")
            self.suspended_pids.discard(pid)
        except Exception as e:
            logger.error(f"[!] Failed to resume process {pid}: {e}")

    save_state()

def show_popup(self, file_path, pid):
    root = tk.Tk()
    root.withdraw()
    root.after(10, root.destroy)  # ✅ ensure popup cleans up

    msg = f"Suspicious file detected:\n{file_path}\n\n"

    proc = None
    pname = "Unknown"
    if pid:
        try:
            proc = psutil.Process(pid)
            pname = proc.name()
        except Exception:
            pass
        msg += f"Detected process: {pname} (PID: {pid})\n\n"
    else:
        msg += "Could not identify process.\n\n"

    msg += "Do you want to DELETE this file and TERMINATE the process?"

    # ✅ Suspend process first
    if proc:
        try:
            proc.suspend()
            logger.info(f"[⏸] Process {pname} (PID: {pid}) suspended.")
            self.suspended_pids.add(pid)
        except Exception as e:
            logger.error(f"[!] Failed to suspend process {pid}: {e}")

    result = messagebox.askyesno("High Entropy Alert!", msg)

    if result:  # ✅ User chose YES
        # Delete suspicious file
        if safe_delete(file_path):
            logger.info(f"[🗑] Deleted suspicious file: {file_path}")
        file_entropy_cache.pop(file_path, None)

        # Kill process tree
        if proc:
            try:
                terminate_process_tree(pid)
                logger.warning(f"[💀] Process tree terminated: {pname} (PID: {pid})")
                self.suspended_pids.discard(pid)
            except Exception as e:
                logger.error(f"[!] Error terminating process {pid}: {e}")

    else:  # ❌ User chose NO → resume process
        if proc:
            try:
                proc.resume()
                logger.info(f"[↩] Process {pname} (PID: {pid}) resumed (user allowed).")
                self.suspended_pids.discard(pid)
            except Exception as e:
                logger.error(f"[!] Failed to resume process {pid}: {e}")

    save_state()
if __name__ == "__main__":
    load_state()
    drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
    observer = Observer()
    handler = EntropyMonitorHandler()

    for drive in drives:
        try:
            observer.schedule(handler, drive, recursive=True)
            logger.info(f"🟢 Monitoring started on: {drive}")
        except Exception as e:
            logger.error(f"🔴 Could not monitor {drive}: {e}")

    observer.start()
    logger.info("🚀 Full system monitoring active.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        save_state()
        observer.stop()
    observer.join()
