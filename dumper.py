import os
import sys
import datetime
import subprocess
import platform
import socket
import argparse
import shutil

def run_cmd(cmd):
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
    except subprocess.CalledProcessError as e:
        output = f"Command failed: {e}\nOutput:\n{e.output}"
    except Exception as e:
        output = f"Error running command {cmd}: {e}"
    return output

def get_local_ips():
    ips = set()
    try:
        hostname = socket.gethostname()
        for res in socket.getaddrinfo(hostname, None):
            addr = res[4][0]
            ips.add(addr)
    except Exception as e:
        ips.add(f"error enumerating via socket: {e}")
    return sorted(ips)

def collect_network_info(out_file):
    with open(out_file, "a", encoding="utf-8") as f:
        f.write(f"Collected: {datetime.datetime.now().isoformat()}\n")
        f.write(f"Platform: {platform.platform()}\n")
        f.write(f"Hostname: {socket.gethostname()}\n\n")

        f.write("=== Local IPs from socket.getaddrinfo ===\n")
        for ip in get_local_ips():
            f.write(f"{ip}\n")

        f.write("\n=== System network config (platform-specific) ===\n")
        if sys.platform.startswith("win"):
            f.write(run_cmd("ipconfig /all"))
        else:
            out = run_cmd("ip addr show")
            if "command not found" in out.lower() or not out.strip():
                out = run_cmd("ifconfig -a")
            f.write(out)

        f.write("\n=== Routing table ===\n")
        if sys.platform.startswith("win"):
            f.write(run_cmd("route print"))
        else:
            f.write(run_cmd("ip route show"))

def find_processes_by_name(name):
    """Return list of (pid, process_name) matching name on current system."""
    results = []
    try:
        if sys.platform.startswith("win"):
            # Use tasklist
            out = run_cmd(f'tasklist /FI "IMAGENAME eq {name}*" /FO CSV /NH')
            # CSV lines like "name","pid","sessionname","session#","memusage"
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                # naive CSV parsing
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    proc_name = parts[0]
                    pid = parts[1]
                    if pid.isdigit():
                        results.append((int(pid), proc_name))
        else:
            # unix: use pgrep to find by pattern (name may be a pattern)
            out = run_cmd(f'pgrep -af "{name}"')
            # lines: "1234 /usr/bin/name args..."
            for line in out.splitlines():
                line = line.strip()
                if not line:
                    continue
                parts = line.split(None, 1)
                if parts and parts[0].isdigit():
                    pid = int(parts[0])
                    proc_name = parts[1] if len(parts) > 1 else name
                    results.append((pid, proc_name))
    except Exception:
        pass
    return results

def create_proc_dump(procdump_path, pid, dump_path):
    """
    Call procdump to create a full memory dump (-ma).
    Returns (success_bool, stdout_or_error).
    """
    if not os.path.isfile(procdump_path):
        return False, f"procdump not found at {procdump_path}"
    cmd = f'"{procdump_path}" -ma {pid} "{dump_path}"'
    try:
        out = run_cmd(cmd)
        return True, out
    except Exception as e:
        return False, str(e)

def main():
    parser = argparse.ArgumentParser(description="Collect network info and optionally create process dumps (Windows).")
    parser.add_argument("--dump", action="store_true", help="Attempt to dump target processes (Windows).")
    parser.add_argument("--procdump-path", type=str, default=None, help="Path to procdump.exe (required if --dump).")
    parser.add_argument("--targets", nargs="+", default=["msedge", "WINWORD", "OUTLOOK", "explorer", "w3wp", "sqlservr"],
                        help="Process base names or patterns to search for (space separated).")
    parser.add_argument("--outdir", type=str, default=None,
                        help="Optional base output directory (default: %%LOCALAPPDATA%%/gather_<timestamp>).")

    # ✅ This line should align with the other parser.add_argument() lines (same indentation)
    args = parser.parse_args()

    time = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = args.outdir if args.outdir else os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), f"gather_{time}")
    os.makedirs(base_dir, exist_ok=True)

    net_file = os.path.join(base_dir, f"network_info_{time}.txt")
    # create initial file
    with open(net_file, "w", encoding="utf-8") as f:
        f.write(f"Gather run at: {datetime.datetime.now().isoformat()}\n")
        f.write(f"User: {os.environ.get('USERNAME') or os.environ.get('USER')}\n")
        f.write(f"Output directory: {base_dir}\n\n")

    # Collect network info
    collect_network_info(net_file)
    print(f"[+] Network info saved to: {net_file}")

    if args.dump:
        if not sys.platform.startswith("win"):
            print("[!] Process dumping (ProcDump) is supported only on Windows in this script.")
            return

        if not args.procdump_path:
            print("[!] --procdump-path is required when using --dump. Download ProcDump from Microsoft Sysinternals and supply its path.")
            return

        procdump_path = args.procdump_path
        if not os.path.isfile(procdump_path) or not procdump_path.lower().endswith("procdump.exe"):
            print(f"[!] Warning: procdump.exe not found at: {procdump_path}")
            # still attempt, but likely will fail
        dumps_dir = os.path.join(base_dir, "dumps")
        os.makedirs(dumps_dir, exist_ok=True)

        summary_lines = []
        for target in args.targets:
            procs = find_processes_by_name(target)
            if not procs:
                print(f"[-] No processes found matching: {target}")
                summary_lines.append(f"No processes for {target}")
                continue

            for pid, proc_name in procs:
                safe_name = f"{proc_name.replace(' ','_')}_{pid}"
                dump_filename = f"{safe_name}_{time}.dmp"
                dump_path = os.path.join(dumps_dir, dump_filename)
                print(f"[+] Creating dump for {proc_name} (PID {pid}) -> {dump_path}")
                success, out = create_proc_dump(procdump_path, pid, dump_path)
                if success:
                    # verify file exists and non-zero
                    if os.path.exists(dump_path) and os.path.getsize(dump_path) > 0:
                        print(f"    Dump created: {dump_path} ({shutil.disk_usage(base_dir).used})")
                        summary_lines.append(f"{proc_name} ({pid}): OK -> {dump_path}")
                    else:
                        print(f"    procdump reported success but dump file missing or zero-sized: {dump_path}")
                        summary_lines.append(f"{proc_name} ({pid}): FAILED (no file)")
                else:
                    print(f"    Failed to create dump for PID {pid}: {out}")
                    summary_lines.append(f"{proc_name} ({pid}): FAILED -> {out}")

        # write summary
        summary_file = os.path.join(base_dir, f"dump_summary_{time}.txt")
        with open(summary_file, "w", encoding="utf-8") as sf:
            sf.write("\n".join(summary_lines))
        print(f"[+] Dump summary saved to: {summary_file}")

    print("[+] All tasks complete.")
    print(f"Output directory: {base_dir}")

if __name__ == "__main__":
    main()
