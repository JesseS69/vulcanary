"""Bounded output and lifecycle for trusted workers, not a hostile-code sandbox."""
import os
import signal
import subprocess
import threading
import time


class WindowsJob:
    def __init__(self, process):
        import ctypes
        from ctypes import wintypes as w
        class Basic(ctypes.Structure):
            _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                        ("flags", w.DWORD), ("min_working", ctypes.c_size_t),
                        ("max_working", ctypes.c_size_t), ("active", w.DWORD),
                        ("affinity", ctypes.c_size_t), ("priority", w.DWORD),
                        ("scheduling", w.DWORD)]
        class IO(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ("read_ops", "write_ops", "other_ops", "read", "write", "other")]
        class Extended(ctypes.Structure):
            _fields_ = [("basic", Basic), ("io", IO), ("process_memory", ctypes.c_size_t),
                        ("job_memory", ctypes.c_size_t), ("peak_process", ctypes.c_size_t),
                        ("peak_job", ctypes.c_size_t)]
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, w.LPCWSTR]
        self.kernel.CreateJobObjectW.restype = w.HANDLE
        self.kernel.SetInformationJobObject.argtypes = [w.HANDLE, ctypes.c_int, ctypes.c_void_p, w.DWORD]
        self.kernel.AssignProcessToJobObject.argtypes = [w.HANDLE, w.HANDLE]
        self.kernel.CloseHandle.argtypes = [w.HANDLE]
        self.handle = self.kernel.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("job_create")
        limits = Extended()
        # Kill on close, bounded tree (venv launchers spawn Python), 256 MiB per process.
        limits.basic.flags = 0x2000 | 0x8 | 0x100
        limits.basic.active = 8
        limits.process_memory = 256 * 1024 * 1024
        if not self.kernel.SetInformationJobObject(self.handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)) or not self.kernel.AssignProcessToJobObject(self.handle, int(process._handle)):
            self.close()
            raise OSError("job_assign")

    def resume(self, process):
        # Popen closes its primary thread handle. Find that still-suspended thread
        # using documented Toolhelp APIs, then resume only after job assignment.
        import ctypes
        from ctypes import wintypes as w
        class ThreadEntry(ctypes.Structure):
            _fields_ = [("size", w.DWORD), ("usage", w.DWORD), ("thread", w.DWORD),
                        ("owner", w.DWORD), ("base_priority", w.LONG),
                        ("delta_priority", w.LONG), ("flags", w.DWORD)]
        kernel = self.kernel
        kernel.CreateToolhelp32Snapshot.argtypes = [w.DWORD, w.DWORD]
        kernel.CreateToolhelp32Snapshot.restype = w.HANDLE
        kernel.Thread32First.argtypes = [w.HANDLE, ctypes.POINTER(ThreadEntry)]
        kernel.Thread32Next.argtypes = [w.HANDLE, ctypes.POINTER(ThreadEntry)]
        kernel.OpenThread.argtypes = [w.DWORD, w.BOOL, w.DWORD]
        kernel.OpenThread.restype = w.HANDLE
        kernel.ResumeThread.argtypes = [w.HANDLE]
        kernel.ResumeThread.restype = w.DWORD
        snapshot = kernel.CreateToolhelp32Snapshot(0x4, 0)
        if snapshot == ctypes.c_void_p(-1).value:
            raise OSError("thread_snapshot")
        try:
            entry = ThreadEntry()
            entry.size = ctypes.sizeof(entry)
            found = kernel.Thread32First(snapshot, ctypes.byref(entry))
            while found:
                if entry.owner == process.pid:
                    thread = kernel.OpenThread(0x2, False, entry.thread)
                    if not thread:
                        raise OSError("thread_open")
                    try:
                        if kernel.ResumeThread(thread) == 0xffffffff:
                            raise OSError("thread_resume")
                        return
                    finally:
                        kernel.CloseHandle(thread)
                found = kernel.Thread32Next(snapshot, ctypes.byref(entry))
            raise OSError("thread_missing")
        finally:
            kernel.CloseHandle(snapshot)

    def close(self):
        if self.handle:
            self.kernel.CloseHandle(self.handle)
            self.handle = None


def run_worker(command, directory, timeout, output_limit=16384):
    environment = {"HOME": str(directory), "USERPROFILE": str(directory),
                   "TMP": str(directory), "TEMP": str(directory), "TMPDIR": str(directory)}
    if os.name == "nt":
        environment["SystemRoot"] = os.environ.get("SystemRoot", r"C:\Windows")
    process = subprocess.Popen(command, cwd=directory, env=environment,
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               start_new_session=os.name != "nt",
                               creationflags=(subprocess.CREATE_NO_WINDOW | 0x4) if os.name == "nt" else 0)
    job, reader = None, None
    output, overflow = bytearray(), threading.Event()
    def drain():
        while True:
            chunk = process.stdout.read(1024)
            if not chunk:
                break
            remaining = output_limit - len(output)
            output.extend(chunk[:max(remaining, 0)])
            if len(chunk) > remaining:
                overflow.set()
    reason = None
    started = time.monotonic()
    try:
        if os.name == "nt":
            job = WindowsJob(process)
            job.resume(process)
        reader = threading.Thread(target=drain, daemon=True)
        reader.start()
        process.stdin.write(b"go\n")
        process.stdin.close()
        while process.poll() is None:
            if overflow.is_set():
                reason = "output_limit"
                break
            if time.monotonic() - started >= timeout:
                reason = "timeout"
                break
            time.sleep(0.01)
    finally:
        # Always close the whole job/group, including after a successful parent exit.
        if job:
            job.close()
        if os.name != "nt":
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        if process.poll() is None:
            process.kill()
        process.wait(timeout=5)
        if reader:
            reader.join(timeout=5)
        process.stdout.close()
        if not process.stdin.closed:
            process.stdin.close()
    if reader and reader.is_alive():
        raise OSError("output_cleanup")
    if overflow.is_set():
        reason = "output_limit"
    return process.returncode, bytes(output), reason
