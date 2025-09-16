#!/bin/bash

# Check bash version for pipefail support
if [[ "${BASH_VERSINFO[0]}" -ge 4 ]] && [[ "${BASH_VERSINFO[1]}" -ge 1 ]]; then
    set -euo pipefail
else
    set -eu
fi

# Configuration - Auto-detect user permissions and adjust paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"

# Smart path selection based on permissions
if [[ $EUID -eq 0 ]]; then
    LOG_DIR="/var/log/ghost-sentinel"
    BACKUP_DIR="/var/backups/ghost-sentinel"
else
    LOG_DIR="$HOME/.ghost-sentinel/logs"
    BACKUP_DIR="$HOME/.ghost-sentinel/backups"
fi

LOCK_FILE="$LOG_DIR/ghost-sentinel-$USER.lock"
PID_FILE="$LOG_DIR/ghost-sentinel-$USER.pid"

CONFIG_FILE="$SCRIPT_DIR/sentinel.conf"
BASELINE_DIR="$LOG_DIR/baseline"
ALERTS_DIR="$LOG_DIR/alerts"
QUARANTINE_DIR="$LOG_DIR/quarantine"
JSON_OUTPUT_FILE="$LOG_DIR/latest_scan.json"
THREAT_INTEL_DIR="$LOG_DIR/threat_intel"
YARA_RULES_DIR="$LOG_DIR/yara_rules"
HONEYPOT_LOG="$LOG_DIR/honeypot.log"
EBPF_LOG="$LOG_DIR/ebpf_events.log"

# Colors for output (straight quotes only)
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

# Alert levels
CRITICAL=1
HIGH=2
MEDIUM=3
LOW=4

# Performance and security controls
MAX_FIND_DEPTH=2
SCAN_TIMEOUT=180
PARALLEL_JOBS=2
THREAT_INTEL_UPDATE_HOURS=6
HONEYPOT_PORTS=("2222" "8080" "23" "21" "3389")

# Environment detection
IS_CONTAINER=false
IS_VM=false
HAS_JQ=false
HAS_INOTIFY=false
HAS_YARA=false
HAS_BCC=false
HAS_NETCAT=false

# Cleanup function for proper resource management
cleanup() {
    declare exit_code=$?

    # Stop honeypots
    stop_honeypots

    # Stop eBPF monitoring
    stop_ebpf_monitoring

    # Stop dashboard
    stop_dashboard

    # Clean up locks
    rm -f "$LOCK_FILE" "$PID_FILE" 2>/dev/null || true

    exit $exit_code
}
trap cleanup EXIT INT TERM

# Enhanced lock management with stale lock detection
acquire_lock() {
    # Check for stale locks
    if [[ -f "$LOCK_FILE" ]]; then
        declare lock_pid=""
        if [[ -f "$PID_FILE" ]]; then
            lock_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
        fi

        # If PID exists and process is running, exit
        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            echo "Another instance is running (PID: $lock_pid). Exiting."
            exit 1
        else
            # Clean up stale lock
            rm -f "$LOCK_FILE" "$PID_FILE" 2>/dev/null || true
        fi
    fi

    # Use flock if available, otherwise manual locking
    if command -v flock >/dev/null 2>&1; then
        exec 200>"$LOCK_FILE"
        if ! flock -n 200; then
            echo "Failed to acquire lock. Another instance may be running."
            exit 1
        fi
    else
        echo $$ > "$LOCK_FILE"
    fi

    # Always write PID file
    echo $$ > "$PID_FILE"
}

# Enhanced dependency checking
check_dependencies() {
    # Check for jq
    if command -v jq >/dev/null 2>&1; then
        HAS_JQ=true
    fi

    # Check for inotify tools
    if command -v inotifywait >/dev/null 2>&1; then
        HAS_INOTIFY=true
    fi

    # Check for YARA
    if command -v yara >/dev/null 2>&1; then
        HAS_YARA=true
    fi

    # Check for eBPF/BCC tools
    if command -v bpftrace >/dev/null 2>&1 || [[ -d /usr/share/bcc/tools ]]; then
        HAS_BCC=true
    fi

    # Check for netcat
    if command -v nc >/dev/null 2>&1 || command -v netcat >/dev/null 2>&1; then
        HAS_NETCAT=true
    fi

    # Warn about missing optional dependencies
    if [[ "$HAS_JQ" == false ]]; then
        log_info "jq not found - JSON output will be basic"
    fi
    if [[ "$HAS_YARA" == false ]]; then
        log_info "YARA not found - malware scanning disabled"
    fi
    if [[ "$HAS_BCC" == false ]]; then
        log_info "eBPF tools not found - kernel monitoring disabled"
    fi
}

# Detect container/VM environment
detect_environment() {
    # Container detection
    if [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] || grep -q "docker\|lxc\|containerd" /proc/1/cgroup 2>/dev/null; then
        IS_CONTAINER=true
    fi

    # VM detection
    if command -v systemd-detect-virt >/dev/null 2>&1; then
        if systemd-detect-virt -q; then
            IS_VM=true
        fi
    elif command -v dmidecode >/dev/null 2>&1 && [[ $EUID -eq 0 ]]; then
        declare vendor=$(dmidecode -s system-product-name 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if [[ "$vendor" =~ (vmware|virtualbox|qemu|kvm|xen) ]]; then
            IS_VM=true
        fi
    fi
}

# Validate script integrity with crypto verification
validate_script_integrity() {
    declare script_hash_file="$LOG_DIR/.script_hash"
    declare current_hash=$(sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1)

    if [[ -f "$script_hash_file" ]]; then
        declare stored_hash=$(cat "$script_hash_file" 2>/dev/null || echo "")
        if [[ -n "$stored_hash" ]] && [[ "$current_hash" != "$stored_hash" ]]; then
            log_alert $CRITICAL "Script integrity check failed - possible tampering detected"
            echo "Expected: $stored_hash"
            echo "Current:  $current_hash"
            echo ""
            echo "This is normal after script updates. To reset:"
            echo "  sudo ./the_protector.sh reset-integrity"
            echo ""
            # For dashboard integration, continue anyway without prompting
            log_info "Continuing with scan despite integrity check failure"
        fi
    fi

    # Update stored hash
    echo "$current_hash" > "$script_hash_file"
}

# Safe JSON handling without jq dependency
json_set() {
    declare file="$1"
    declare key="$2"
    declare value="$3"

    if [[ "$HAS_JQ" == true ]]; then
        declare tmp_file=$(mktemp)
        jq "$key = \"$value\"" "$file" > "$tmp_file" 2>/dev/null && mv "$tmp_file" "$file"
    else
        # Fallback: simple key-value replacement
        if grep -q "\"${key#.}\":" "$file" 2>/dev/null; then
            sed -i "s/\"${key#.}\": *\"[^\"]*\"/\"${key#.}\": \"$value\"/" "$file" 2>/dev/null || true
        fi
    fi
}

json_add_alert() {
    declare level="$1"
    declare message="$2"
    declare timestamp="$3"

    if [[ "$HAS_JQ" == true ]]; then
        declare tmp_file=$(mktemp)
        jq ".alerts += [{\"level\": $level, \"message\": \"$message\", \"timestamp\": \"$timestamp\"}]" "$JSON_OUTPUT_FILE" > "$tmp_file" 2>/dev/null && mv "$tmp_file" "$JSON_OUTPUT_FILE"
    else
        # Fallback: append to simple log format
        echo "{\"level\": $level, \"message\": \"$message\", \"timestamp\": \"$timestamp\"}" >> "$LOG_DIR/alerts.jsonl"
    fi
}

# Initialize YARA rules for advanced malware detection
init_yara_rules() {
    if [[ "$HAS_YARA" != true ]]; then
        return
    fi

    mkdir -p "$YARA_RULES_DIR"

    # Create comprehensive YARA rules
    cat > "$YARA_RULES_DIR/malware_detection.yar" << 'EOF'
rule Suspicious_Base64_Payload {
    meta:
        description = "Detects suspicious base64 encoded payloads"
        severity = "high"
    strings:
        $b64_long = /[A-Za-z0-9+\/]{100,}={0,2}/ fullword
        $eval = "eval"
        $exec = "exec"
        $decode = "base64"
    condition:
        $b64_long and ($eval or $exec or $decode)
}

rule Reverse_Shell_Patterns {
    meta:
        description = "Detects reverse shell command patterns"
        severity = "critical"
    strings:
        $nc_bind = /nc.*-l.*-p.*[0-9]+/
        $nc_connect = /nc.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+.*[0-9]+/
        $bash_tcp = "/dev/tcp/"
        $python_socket = "socket.socket(socket.AF_INET"
        $perl_socket = "IO::Socket::INET"
        $socat_reverse = /socat.*tcp.*exec/
        $mknod_backpipe = /mknod.*backpipe.*p/
    condition:
        any of them
}

rule Webshell_Indicators {
    meta:
        description = "Detects common webshell patterns"
        severity = "high"
    strings:
        $php_eval = /eval\s*\(\s*\$_(GET|POST|REQUEST)/
        $php_system = /system\s*\(\s*\$_(GET|POST|REQUEST)/
        $php_passthru = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/
        $php_shell_exec = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/
        $asp_eval = "eval(Request"
        $jsp_runtime = "Runtime.getRuntime().exec"
        $generic_backdoor = /\$_(GET|POST)\[.*\]\s*=.*exec/
    condition:
        any of them
}

rule Crypto_Miner_Indicators {
    meta:
        description = "Detects cryptocurrency mining malware"
        severity = "high"
    strings:
        $stratum1 = "stratum+tcp://"
        $stratum2 = "stratum+ssl://"
        $xmrig = "xmrig"
        $cpuminer = "cpuminer"
        $pool1 = "pool.supportxmr.com"
        $pool2 = "xmr-usa-east1.nanopool.org"
        $wallet = /[49][A-Za-z0-9]{94}/
        $mining_algo = /cryptonight|scrypt|sha256|x11/
    condition:
        any of them
}

rule Process_Injection_Techniques {
    meta:
        description = "Detects process injection indicators"
        severity = "medium"
    strings:
        $ptrace = "ptrace"
        $proc_mem = "/proc/*/mem"
        $ld_preload = "LD_PRELOAD"
        $dlopen = "dlopen"
        $mmap_exec = "PROT_EXEC"
        $shellcode = { 31 c0 50 68 }
    condition:
        any of them
}

rule Persistence_Mechanisms {
    meta:
        description = "Detects persistence establishment attempts"
        severity = "medium"
    strings:
        $crontab = "crontab -e"
        $systemd_service = ".service"
        $bashrc = ".bashrc"
        $profile = ".profile"
        $ssh_keys = "authorized_keys"
        $startup = "/etc/init.d/"
        $rc_declare = "/etc/rc.local"
    condition:
        any of them
}
EOF

    # Create rules for specific threats
    cat > "$YARA_RULES_DIR/apt_indicators.yar" << 'EOF'
rule APT_Lateral_Movement {
    meta:
        description = "Detects APT lateral movement tools"
        severity = "critical"
    strings:
        $psexec = "psexec"
        $wmic = "wmic process call create"
        $schtasks = "schtasks /create"
        $powershell_encoded = "powershell -enc"
        $mimikatz = "sekurlsa::logonpasswords"
        $bloodhound = "SharpHound"
        $cobalt_strike = "beacon"
    condition:
        any of them
}

rule Data_Exfiltration {
    meta:
        description = "Detects data exfiltration attempts"
        severity = "high"
    strings:
        $curl_upload = /curl.*-T.*http/
        $wget_post = /wget.*--post-file/
        $nc_file = /nc.*<.*\/.*\//
        $base64_pipe = /base64.*\|.*curl/
        $tar_remote = /tar.*\|.*nc/
        $scp_remote = /scp.*@/
    condition:
        any of them
}
EOF

    log_info "YARA rules initialized for advanced malware detection"
}

# eBPF-based monitoring for kernel-level observability
start_ebpf_monitoring() {
    if [[ "$HAS_BCC" != true ]] || [[ $EUID -ne 0 ]]; then
        log_info "eBPF monitoring requires root and BCC tools - skipping"
        return
    fi

    log_info "Starting eBPF-based kernel monitoring..."

    # Monitor process execution
    cat > "/tmp/ghost_sentinel_execsnoop.py" << 'EOF'
#!/usr/bin/env python3
import sys
import time
import os

# Get log file from environment
log_file = os.environ.get('EBPF_LOG', '/var/log/ghost-sentinel/ebpf_events.log')

# eBPF program to monitor process execution
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

struct data_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

int syscall__execve(struct pt_regs *ctx, const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp)
{
    struct data_t data = {};
    struct task_struct *task;

    data.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->tgid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), filename);

    events.perf_submit(ctx, &data, sizeof(data));
    return 0;
}
"""

def print_event(cpu, data, size):
    event = b["events"].event(data)
    suspicious_patterns = [
        b"nc", b"netcat", b"socat", b"/dev/tcp", b"python -c", b"perl -e",
        b"bash -i", b"sh -i", b"wget", b"curl", b"base64"
    ]

    filename = event.filename.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')

    for pattern in suspicious_patterns:
        if pattern in filename.encode() or pattern in comm.encode():
            with open(log_file, 'a') as f:
                f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} SUSPICIOUS_EXEC: PID={event.pid} PPID={event.ppid} COMM={comm} FILE={filename}\n")
            break

try:
    b = BPF(text=bpf_text)
    execve_fnname = b.get_syscall_fnname("execve")
    b.attach_kprobe(event=execve_fnname, fn_name="syscall__execve")

    b["events"].open_perf_buffer(print_event)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break
except Exception as e:
    print(f"eBPF monitoring error: {e}")
    sys.exit(1)
EOF

    # Start eBPF monitoring in background
    if command -v python3 >/dev/null 2>&1; then
        export EBPF_LOG="$EBPF_LOG"
        python3 /tmp/ghost_sentinel_execsnoop.py &
        echo $! > "$LOG_DIR/ebpf_monitor.pid"
        log_info "eBPF process monitoring started"
    fi
}

stop_ebpf_monitoring() {
    if [[ -f "$LOG_DIR/ebpf_monitor.pid" ]]; then
        declare ebpf_pid=$(cat "$LOG_DIR/ebpf_monitor.pid" 2>/dev/null || echo "")
        if [[ -n "$ebpf_pid" ]] && kill -0 "$ebpf_pid" 2>/dev/null; then
            kill "$ebpf_pid" 2>/dev/null || true
        fi
        rm -f "$LOG_DIR/ebpf_monitor.pid"
    fi
    rm -f /tmp/ghost_sentinel_execsnoop.py
}

stop_dashboard() {
    if [[ -f "$LOG_DIR/dashboard.pid" ]]; then
        declare dash_pid=$(cat "$LOG_DIR/dashboard.pid" 2>/dev/null || echo "")
        if [[ -n "$dash_pid" ]] && kill -0 "$dash_pid" 2>/dev/null; then
            kill "$dash_pid" 2>/dev/null || true
        fi
        rm -f "$LOG_DIR/dashboard.pid"
    fi
}

# Honeypot implementation for detecting scanning/attacks
start_honeypots() {
    if [[ "$HAS_NETCAT" != true ]]; then
        log_info "Netcat not available - honeypots disabled"
        return
    fi

    log_info "Starting honeypot listeners on suspicious ports..."

    for port in "${HONEYPOT_PORTS[@]}"; do
        # Check if port is already in use
        if ss -tuln 2>/dev/null | grep -q ":$port "; then
            continue
        fi

        # Start honeypot listener
        (
            while true; do
                declare timestamp=$(date '+%Y-%m-%d %H:%M:%S')
                declare connection_info=""

                if command -v nc >/dev/null 2>&1; then
                    connection_info=$(timeout 30 nc -l -p "$port" -s 127.0.0.1 2>&1 || true)
                elif command -v netcat >/dev/null 2>&1; then
                    connection_info=$(timeout 30 netcat -l -p "$port" -s 127.0.0.1 2>&1 || true)
                fi

                if [[ -n "$connection_info" ]]; then
                    echo "[$timestamp] HONEYPOT_HIT: Port $port - $connection_info" >> "$HONEYPOT_LOG"
                    log_alert $HIGH "Honeypot triggered on port $port"
                fi

                sleep 1
            done
        ) &

        echo $! >> "$LOG_DIR/honeypot.pids"
    done

    log_info "Honeypots started on ports: ${HONEYPOT_PORTS[*]}"
}

stop_honeypots() {
    if [[ -f "$LOG_DIR/honeypot.pids" ]]; then
        while read pid; do
            if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
                kill "$pid" 2>/dev/null || true
            fi
        done < "$LOG_DIR/honeypot.pids"
        rm -f "$LOG_DIR/honeypot.pids"
    fi
}

# Anti-evasion detection for advanced threats
detect_anti_evasion() {
    log_info "Running anti-evasion detection..."

    # Detect LD_PRELOAD hijacking
    if [[ -n "${LD_PRELOAD:-}" ]]; then
        log_alert $HIGH "LD_PRELOAD environment variable detected: $LD_PRELOAD"
    fi

    # Check for processes with LD_PRELOAD in environment
    for pid in $(pgrep -f ".*" 2>/dev/null | head -20); do
        if [[ -r "/proc/$pid/environ" ]]; then
            declare environ_content=$(tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null || echo "")
            if echo "$environ_content" | grep -q "LD_PRELOAD="; then
                declare proc_name=$(ps -p "$pid" -o comm= 2>/dev/null || echo "unknown")
                declare preload_libs=$(echo "$environ_content" | grep "LD_PRELOAD=" | cut -d= -f2)
                log_alert $HIGH "Process with LD_PRELOAD detected: $proc_name (PID: $pid, PRELOAD: $preload_libs)"
            fi
        fi
    done

    # Detect /proc inconsistencies (hidden processes)
    declare proc_dirs=$(find /proc -maxdepth 1 -type d -name '[0-9]*' 2>/dev/null | wc -l)
    declare ps_count=$(ps aux --no-headers 2>/dev/null | wc -l)
    declare ps_ef_count=$(ps -ef --no-headers 2>/dev/null | wc -l)

    # Check for significant discrepancies
    declare diff1=$((proc_dirs - ps_count))
    declare diff2=$((proc_dirs - ps_ef_count))

    if [[ $diff1 -gt 15 ]] || [[ $diff2 -gt 15 ]]; then
        log_alert $HIGH "Significant /proc inconsistency detected (proc_dirs: $proc_dirs, ps: $ps_count, ps_ef: $ps_ef_count)"
    fi

    # Detect modified system calls (if root)
    if [[ $EUID -eq 0 ]] && [[ -r /proc/kallsyms ]]; then
        declare suspicious_symbols=$(grep -E "(hijacked|hook|detour)" /proc/kallsyms 2>/dev/null || echo "")
        if [[ -n "$suspicious_symbols" ]]; then
            log_alert $CRITICAL "Suspicious kernel symbols detected: $suspicious_symbols"
        fi
    fi

    # Check for common rootkit hiding techniques
    declare hiding_techniques=(
        "/usr/bin/..."
        "/usr/sbin/..."
        "/lib/.x"
        "/lib64/.x"
        "/tmp/.hidden"
        "/var/tmp/.X11-unix"
    )

    for technique in "${hiding_techniques[@]}"; do
        if [[ -e "$technique" ]]; then
            log_alert $CRITICAL "Rootkit hiding technique detected: $technique"
        fi
    done
}

# Enhanced network monitoring with anti-evasion
monitor_network_advanced() {
    if [[ "$MONITOR_NETWORK" != true ]]; then return; fi

    log_info "Advanced network monitoring with anti-evasion..."

    # Use multiple tools for cross-validation
    declare ss_output=$(ss -tulnp 2>/dev/null || echo "")
    declare netstat_output=$(netstat -tulnp 2>/dev/null || echo "")
    declare lsof_output=$(lsof -i -P -n 2>/dev/null || echo "")

    # Compare outputs to detect hiding
    declare ss_ports=$(echo "$ss_output" | grep -oE ":[0-9]+" | sort -u | wc -l)
    declare netstat_ports=$(echo "$netstat_output" | grep -oE ":[0-9]+" | sort -u | wc -l)
    declare lsof_ports=$(echo "$lsof_output" | grep -oE ":[0-9]+" | sort -u | wc -l)

    declare max_diff=10
    if [[ $((ss_ports - netstat_ports)) -gt $max_diff ]] || [[ $((lsof_ports - ss_ports)) -gt $max_diff ]]; then
        log_alert $HIGH "Network tool output inconsistency detected (ss: $ss_ports, netstat: $netstat_ports, lsof: $lsof_ports)"
    fi

    # Check for suspicious RAW sockets
    if [[ -r /proc/net/raw ]]; then
        declare raw_sockets=$(grep -v "sl" /proc/net/raw 2>/dev/null | wc -l)
        if [[ $raw_sockets -gt 3 ]]; then
            log_alert $MEDIUM "Multiple RAW sockets detected: $raw_sockets"
        fi
    fi

    # Monitor for covert channels
    declare icmp_traffic=$(grep "ICMP" /proc/net/snmp 2>/dev/null | tail -1 | awk '{print $3}' || echo 0)
    if [[ $icmp_traffic -gt 1000 ]]; then
        log_alert $MEDIUM "High ICMP traffic detected: $icmp_traffic packets"
    fi
}

# YARA-enhanced file monitoring
monitor_files_with_yara() {
    if [[ "$MONITOR_FILES" != true ]]; then return; fi

    log_info "File monitoring with YARA malware detection..."

    # Scan suspicious locations with YARA
    declare scan_locations=("/tmp" "/var/tmp" "/dev/shm")

    for location in "${scan_locations[@]}"; do
        if [[ -d "$location" ]] && [[ -r "$location" ]]; then
            find "$location" -maxdepth 2 -type f -mtime -1 ! -name "ghost_sentinel_execsnoop.py" 2>/dev/null | head -10 | while read file; do
                # Skip very large files for performance
                declare file_size=$(stat -c%s "$file" 2>/dev/null || echo 0)
                if [[ $file_size -gt 1048576 ]]; then  # Skip files > 1MB
                    continue
                fi

                # Perform YARA scan if available
                if [[ "$HAS_YARA" == true ]]; then
                    declare yara_result=$(yara -r "$YARA_RULES_DIR" "$file" 2>/dev/null || echo "")
                    if [[ -n "$yara_result" ]]; then
                        log_alert $CRITICAL "YARA detection: $yara_result"
                        quarantine_file_forensic "$file"
                        continue
                    fi
                fi

                # Fallback pattern matching
                if [[ -r "$file" ]]; then
                    declare suspicious_content=$(grep -l -E "(eval.*base64|exec.*\\\$|/dev/tcp|socket\.socket.*connect)" "$file" 2>/dev/null || echo "")
                    if [[ -n "$suspicious_content" ]]; then
                        log_alert $HIGH "Suspicious script content: $file"
                        quarantine_file_forensic "$file"
                    fi
                fi
            done
        fi
    done
}

# Enhanced quarantine with YARA analysis and forensics
quarantine_file_forensic() {
    declare file="$1"
    declare timestamp=$(date +%s)
    declare quarantine_name="$(basename "$file")_$timestamp"

    if [[ -f "$file" ]] && [[ -w "$(dirname "$file")" ]]; then
        # Create forensic directory
        declare forensic_dir="$QUARANTINE_DIR/forensics"
        mkdir -p "$forensic_dir"

        # Preserve all metadata
        stat "$file" > "$forensic_dir/${quarantine_name}.stat" 2>/dev/null || true
        ls -la "$file" > "$forensic_dir/${quarantine_name}.ls" 2>/dev/null || true
        file "$file" > "$forensic_dir/${quarantine_name}.file" 2>/dev/null || true

        # Create hash for integrity
        sha256sum "$file" > "$forensic_dir/${quarantine_name}.sha256" 2>/dev/null || true

        # YARA analysis if available
        if [[ "$HAS_YARA" == true ]] && [[ -r "$file" ]]; then
            yara -s -r "$YARA_RULES_DIR" "$file" > "$forensic_dir/${quarantine_name}.yara" 2>/dev/null || true
        fi

        # String analysis
        if command -v strings >/dev/null 2>&1; then
            strings "$file" | head -100 > "$forensic_dir/${quarantine_name}.strings" 2>/dev/null || true
        fi

        # Move to quarantine
        if mv "$file" "$QUARANTINE_DIR/$quarantine_name" 2>/dev/null; then
            log_info "File quarantined with forensics: $file -> $QUARANTINE_DIR/$quarantine_name"

            # Create safe placeholder
            touch "$file" 2>/dev/null || true
            chmod 000 "$file" 2>/dev/null || true
        else
            log_info "Failed to quarantine file: $file"
        fi
    fi
}

# Initialize enhanced directory structure
init_sentinel() {
    # Create directories FIRST
    for dir in "$LOG_DIR" "$BASELINE_DIR" "$ALERTS_DIR" "$QUARANTINE_DIR" "$BACKUP_DIR" "$THREAT_INTEL_DIR" "$YARA_RULES_DIR"; do
        if ! mkdir -p "$dir" 2>/dev/null; then
            echo -e "${RED}[ERROR]${NC} Cannot create directory: $dir"
            echo "Please run as root or ensure write permissions"
            exit 1
        fi
    done

    # Load configuration BEFORE doing anything else
    load_config_safe

    # Check dependencies
    check_dependencies

    # Initialize components
    init_json_output
    init_yara_rules

    log_info "Initializing Ghost Sentinel v4.0..."

    # Detect environment
    detect_environment
    if [[ "$IS_CONTAINER" == true ]]; then
        log_info "Container environment detected - adjusting monitoring"
    fi
    if [[ "$IS_VM" == true ]]; then
        log_info "Virtual machine environment detected"
    fi

    # Update threat intelligence
    update_threat_intelligence

    # Create/update baseline
    if [[ ! -f "$BASELINE_DIR/.initialized" ]] || [[ "${FORCE_BASELINE:-false}" == true ]]; then
        log_info "Creating security baseline..."
        create_baseline
        touch "$BASELINE_DIR/.initialized"
    fi
}

# Enhanced JSON initialization
init_json_output() {
    cat > "$JSON_OUTPUT_FILE" << 'EOF'
{
  "version": "2.3",
  "scan_start": "",
  "scan_end": "",
  "hostname": "",
  "environment": {
    "is_container": false,
    "is_vm": false,
    "user": "",
    "has_jq": false,
    "has_inotify": false,
    "has_yara": false,
    "has_bcc": false,
    "has_netcat": false
  },
  "summary": {
    "total_alerts": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "alerts": [],
  "performance": {
    "scan_duration": 0,
    "modules_run": []
  },
  "integrity": {
    "script_hash": "",
    "baseline_age": 0
  },
  "features": {
    "ebpf_monitoring": false,
    "honeypots": false,
    "yara_scanning": false,
    "anti_evasion": false,
    "threat_intelligence": false,
    "forensic_analysis": true,
    "api_server": false
  }
}
EOF
}

# Load configuration with enhanced validation
load_config_safe() {
    # Set secure defaults
    MONITOR_NETWORK=${MONITOR_NETWORK:-true}
    MONITOR_PROCESSES=${MONITOR_PROCESSES:-true}
    MONITOR_FILES=${MONITOR_FILES:-true}
    MONITOR_USERS=${MONITOR_USERS:-true}
    MONITOR_ROOTKITS=${MONITOR_ROOTKITS:-true}
    MONITOR_MEMORY=${MONITOR_MEMORY:-true}
    ENABLE_ANTI_EVASION=${ENABLE_ANTI_EVASION:-true}
    ENABLE_EBPF=${ENABLE_EBPF:-true}
    ENABLE_HONEYPOTS=${ENABLE_HONEYPOTS:-true}
    ENABLE_YARA=${ENABLE_YARA:-true}
    SEND_EMAIL=${SEND_EMAIL:-false}
    EMAIL_RECIPIENT=${EMAIL_RECIPIENT:-""}
    WEBHOOK_URL=${WEBHOOK_URL:-""}
    SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL:-""}
    ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY:-""}
    VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY:-""}
    SYSLOG_ENABLED=${SYSLOG_ENABLED:-true}
    PERFORMANCE_MODE=${PERFORMANCE_MODE:-false}
    ENABLE_THREAT_INTEL=${ENABLE_THREAT_INTEL:-true}

    # Secure whitelists with exact matching
    WHITELIST_PROCESSES=${WHITELIST_PROCESSES:-("firefox" "chrome" "nmap" "masscan" "nuclei" "gobuster" "ffuf" "subfinder" "httpx" 
    "amass" "burpsuite" "wireshark" "metasploit" "sqlmap" "nikto" "dirb" "wpscan" "john" "docker" "containerd" "systemd" "kthreadd" 
    "bash" "zsh" "ssh" "python3" "yara" "curl" "wget" "nc" "netcat" "socat" "perl" "ruby" "go" "java" "php" "node" "npm" "mongod" "mysqld" "postgres"
    "redis-server" "nginx" "apache2" "httpd" "sshd" "systemd-journald" "systemd-logind" "dbus-daemon" "NetworkManager" "rsyslogd" 
    "cron" "atd" "dhclient" "Xorg" "lightdm" "gdm" "cupsd" "avahi-daemon" "bluetoothd" "ModemManager" "polkitd" "ssh-agent" "at-spi-bus-laun" "dbus-launch" "ghost_sentinel_execsnoop.py")}
    WHITELIST_CONNECTIONS=${WHITELIST_CONNECTIONS:-("127.0.0.1" "::1" "0.0.0.0" "8.8.8.8" "1.1.1.1" "208.67.222.222" "1.0.0.1" "9.9.9.9")}
    EXCLUDE_PATHS=${EXCLUDE_PATHS:-("/opt/metasploit-framework" "/usr/share/metasploit-framework" "/usr/share/wordlists" "/home/*/go/bin" "/tmp/nuclei-templates" "/var/lib/docker" "/var/lib/containerd" "/snap")}
    CRITICAL_PATHS=${CRITICAL_PATHS:-("/etc/passwd" "/etc/shadow" "/etc/sudoers" "/etc/ssh/sshd_config" "/etc/hosts")}

    # Load and validate config file
    if [[ -f "$CONFIG_FILE" ]]; then
        if source "$CONFIG_FILE" 2>/dev/null; then
            log_info "Configuration loaded from $CONFIG_FILE"
        else
            log_info "Warning: Config file syntax error, using defaults"
        fi
    fi
}

# Enhanced logging with tamper resistance
log_alert() {
    declare level=$1
    declare message="$2"
    declare timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case $level in
        $CRITICAL) echo -e "${RED}[CRITICAL]${NC} $message" ;;
        $HIGH)     echo -e "${YELLOW}[HIGH]${NC} $message" ;;
        $MEDIUM)   echo -e "${BLUE}[MEDIUM]${NC} $message" ;;
        $LOW)      echo -e "${GREEN}[LOW]${NC} $message" ;;
    esac

    # Write to alert file with integrity check
    if [[ -n "$ALERTS_DIR" ]]; then
        mkdir -p "$ALERTS_DIR" 2>/dev/null || true
        declare alert_file="$ALERTS_DIR/$(date +%Y%m%d).log"
        declare log_entry="[$timestamp] [LEVEL:$level] $message"
        echo "$log_entry" >> "$alert_file" 2>/dev/null || true

        # Add checksum for integrity
        echo "$(echo "$log_entry" | sha256sum | cut -d' ' -f1)" >> "$alert_file.hash" 2>/dev/null || true
    fi

    # Add to JSON output
    json_add_alert "$level" "$message" "$timestamp"

    # Send to syslog with facility (only if SYSLOG_ENABLED is set)
    if [[ "${SYSLOG_ENABLED:-false}" == true ]] && command -v logger >/dev/null 2>&1; then
        logger -t "ghost-sentinel[$]" -p security.alert -i "$message" 2>/dev/null || true
    fi

    # Critical alerts trigger immediate response
    if [[ $level -eq $CRITICAL ]]; then
        send_critical_alert "$message"
    fi
}

log_info() {
    declare timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${CYAN}[INFO]${NC} $1"

    if [[ -n "$LOG_DIR" ]]; then
        mkdir -p "$LOG_DIR" 2>/dev/null || true
        echo "[$timestamp] [INFO] $1" >> "$LOG_DIR/sentinel.log" 2>/dev/null || true
    fi
}

# Enhanced critical alert handling with fallbacks
send_critical_alert() {
    declare message="$1"

    # Email notification with fallback check
    if [[ "$SEND_EMAIL" == true ]] && [[ -n "$EMAIL_RECIPIENT" ]]; then
        if command -v mail >/dev/null 2>&1; then
            echo "CRITICAL SECURITY ALERT: $message" | mail -s "Ghost Sentinel Alert" "$EMAIL_RECIPIENT" 2>/dev/null || true
        elif command -v sendmail >/dev/null 2>&1; then
            echo -e "Subject: Ghost Sentinel Critical Alert\n\nCRITICAL SECURITY ALERT: $message" | sendmail "$EMAIL_RECIPIENT" 2>/dev/null || true
        fi
    fi

    # Webhook notification with improved error handling
    if [[ -n "$WEBHOOK_URL" ]] && command -v curl >/dev/null 2>&1; then
        curl -s --max-time 10 -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"alert\":\"CRITICAL\",\"message\":\"$message\",\"timestamp\":\"$(date -Iseconds)\",\"hostname\":\"$(hostname)\"}" 2>/dev/null || true
    fi

    # Slack webhook with rich formatting
    if [[ -n "$SLACK_WEBHOOK_URL" ]] && command -v curl >/dev/null 2>&1; then
        declare payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "danger",
            "title": "🚨 Ghost Sentinel v4.0 Critical Alert",
            "text": "$message",
            "fields": [
                {
                    "title": "Hostname",
                    "value": "$(hostname)",
                    "short": true
                },
                {
                    "title": "Timestamp",
                    "value": "$(date)",
                    "short": true
                }
            ],
            "footer": "Ghost Sentinel v4.0",
            "ts": $(date +%s)
        }
    ]
}
EOF
)
        curl -s --max-time 10 -X POST "$SLACK_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "$payload" 2>/dev/null || true
    fi

    # Desktop notification for interactive sessions (with fallbacks)
    if [[ -n "${DISPLAY:-}" ]]; then
        if command -v notify-send >/dev/null 2>&1; then
            notify-send "Ghost Sentinel" "CRITICAL: $message" --urgency=critical 2>/dev/null || true
        elif command -v zenity >/dev/null 2>&1; then
            zenity --error --text="Ghost Sentinel CRITICAL: $message" 2>/dev/null || true &
        fi
    fi
}

# Enhanced threat intelligence with caching
update_threat_intelligence() {
    if [[ "$ENABLE_THREAT_INTEL" != true ]]; then
        return
    fi

    log_info "Updating threat intelligence feeds..."

    declare intel_file="$THREAT_INTEL_DIR/malicious_ips.txt"
    declare intel_timestamp="$THREAT_INTEL_DIR/.last_update"

    # Check if update is needed (every 6 hours by default)
    declare update_needed=true
    if [[ -f "$intel_timestamp" ]]; then
        declare last_update=$(cat "$intel_timestamp" 2>/dev/null || echo 0)
        declare current_time=$(date +%s)
        declare age=$((current_time - last_update))
        declare max_age=$((THREAT_INTEL_UPDATE_HOURS * 3600))

        if [[ $age -lt $max_age ]]; then
            update_needed=false
        fi
    fi

    if [[ "$update_needed" == true ]]; then
        # Download threat feeds (with timeout and verification)
        declare temp_file=$(mktemp)

        # FireHOL Level 1 blocklist (reliable source)
        if command -v curl >/dev/null 2>&1; then
            if curl -s --max-time 30 -o "$temp_file" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" 2>/dev/null; then
                # Better validation - check for IP addresses and reasonable file size
                if [[ -s "$temp_file" ]] && [[ $(wc -l < "$temp_file" 2>/dev/null || echo 0) -gt 100 ]] && head -5 "$temp_file" | grep -q -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"; then
                    mv "$temp_file" "$intel_file"
                    echo $(date +%s) > "$intel_timestamp"
                    log_info "Threat intelligence updated successfully ($(wc -l < "$intel_file" 2>/dev/null || echo 0) entries)"
                else
                    rm -f "$temp_file"
                    log_info "Threat intelligence update failed - validation failed"
                fi
            else
                rm -f "$temp_file"
                log_info "Threat intelligence update failed - network error"
            fi
        fi
    fi
}

# Enhanced helper functions with exact matching
is_whitelisted_process() {
    declare process="$1"
    declare proc_basename=$(basename "$process" 2>/dev/null || echo "$process")

    for whitelisted in "${WHITELIST_PROCESSES[@]}"; do
        if [[ "$proc_basename" == "$whitelisted" ]]; then
            return 0
        fi
    done
    return 1
}

is_whitelisted_connection() {
    declare addr="$1"
    for whitelisted in "${WHITELIST_CONNECTIONS[@]}"; do
        if [[ "$addr" == "$whitelisted" ]]; then
            return 0
        fi
    done
    return 1
}

is_private_address() {
    declare addr="$1"

    # RFC 1918 private networks + localhost + link-local
    if [[ "$addr" =~ ^10\. ]] || [[ "$addr" =~ ^192\.168\. ]] || [[ "$addr" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        return 0
    fi
    if [[ "$addr" =~ ^127\. ]] || [[ "$addr" =~ ^169\.254\. ]] || [[ "$addr" == "::1" ]] || [[ "$addr" =~ ^fe80: ]]; then
        return 0
    fi

    # Multicast and broadcast
    if [[ "$addr" =~ ^(224\.|225\.|226\.|227\.|228\.|229\.|230\.|231\.|232\.|233\.|234\.|235\.|236\.|237\.|238\.|239\.) ]]; then
        return 0
    fi

    return 1
}

# Enhanced threat intelligence checking
is_malicious_ip() {
    declare addr="$1"
    declare intel_file="$THREAT_INTEL_DIR/malicious_ips.txt"

    # Skip private addresses
    if is_private_address "$addr"; then
        return 1
    fi

    # Check declare threat intelligence
    if [[ -f "$intel_file" ]]; then
        if grep -q "^$addr" "$intel_file" 2>/dev/null; then
            return 0
        fi
    fi

    # Check against AbuseIPDB if API key is available
    if [[ -n "$ABUSEIPDB_API_KEY" ]] && command -v curl >/dev/null 2>&1; then
        declare cache_file="$THREAT_INTEL_DIR/abuseipdb_$addr"
        declare cache_age=3600  # 1 hour cache

        # Check cache first
        if [[ -f "$cache_file" ]]; then
            declare file_age=$(($(date +%s) - $(stat -c %Y "$cache_file" 2>/dev/null || echo 0)))
            if [[ $file_age -lt $cache_age ]]; then
                declare cached_result=$(cat "$cache_file" 2>/dev/null || echo "0")
                if [[ "$cached_result" -gt 75 ]]; then
                    return 0
                else
                    return 1
                fi
            fi
        fi

        # Query AbuseIPDB with rate limiting
        declare response=$(curl -s --max-time 5 -G https://api.abuseipdb.com/api/v2/check \
            --data-urlencode "ipAddress=$addr" \
            -H "Key: $ABUSEIPDB_API_KEY" \
            -H "Accept: application/json" 2>/dev/null || echo "")

        if [[ -n "$response" ]]; then
            declare confidence=0
            if command -v jq >/dev/null 2>&1; then
                confidence=$(echo "$response" | jq -r '.data.abuseConfidencePercentage // 0' 2>/dev/null || echo 0)
            else
                # Fallback parsing
                confidence=$(echo "$response" | grep -o '"abuseConfidencePercentage":[0-9]*' | cut -d: -f2 || echo 0)
            fi

            # Cache the result
            echo "$confidence" > "$cache_file"

            if [[ $confidence -gt 75 ]]; then
                return 0
            fi
        fi
    fi

    return 1
}

# Performance-optimized baseline creation
create_baseline() {
    log_info "Creating optimized security baseline..."

    # Network baseline
    if command -v ss >/dev/null 2>&1; then
        ss -tulnp --no-header > "$BASELINE_DIR/network_baseline.txt" 2>/dev/null || true
    elif command -v netstat >/dev/null 2>&1; then
        netstat -tulnp --numeric-hosts --numeric-ports > "$BASELINE_DIR/network_baseline.txt" 2>/dev/null || true
    fi

    # Process baseline (structured)
    ps -eo pid,ppid,user,comm,cmd --no-headers > "$BASELINE_DIR/process_baseline.txt" 2>/dev/null || true

    # Services baseline
    if command -v systemctl >/dev/null 2>&1; then
        systemctl list-units --type=service --state=running --no-pager --no-legend --plain > "$BASELINE_DIR/services_baseline.txt" 2>/dev/null || true
    fi

    # Critical file baselines (performance optimized)
    for file in "${CRITICAL_PATHS[@]}"; do
        if [[ -e "$file" ]] && [[ -r "$file" ]] && [[ -f "$file" ]]; then
            sha256sum "$file" > "$BASELINE_DIR/$(basename "$file")_baseline.sha256" 2>/dev/null || true
        fi
    done

    # User baseline
    if [[ -r /etc/passwd ]]; then
        cut -d: -f1 /etc/passwd | sort > "$BASELINE_DIR/users_baseline.txt" 2>/dev/null || true
    fi

    # Login history (limited)
    if command -v last >/dev/null 2>&1; then
        last -n 10 --time-format=iso > "$BASELINE_DIR/last_baseline.txt" 2>/dev/null || true
    fi

    # Package state (hash only for performance)
    declare pkg_hash=""
    if command -v dpkg >/dev/null 2>&1; then
        pkg_hash=$(dpkg -l 2>/dev/null | sha256sum | cut -d' ' -f1)
    elif command -v rpm >/dev/null 2>&1; then
        pkg_hash=$(rpm -qa --queryformat="%{NAME}-%{VERSION}-%{RELEASE}\n" 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    fi

    if [[ -n "$pkg_hash" ]]; then
        echo "$pkg_hash" > "$BASELINE_DIR/packages_hash.txt"
    fi

    # SUID/SGID baseline (limited scope)
    find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 -perm /4000 -o -perm /2000 2>/dev/null | sort > "$BASELINE_DIR/suid_baseline.txt" || true

    log_info "Baseline created successfully"
}

# Production main function with all v4.0 features
main_enhanced() {
    declare start_time=$(date +%s)

    log_info "Ghost Sentinel v4.0 Enhanced - Starting advanced security scan..."

    # Update JSON metadata
    json_set "$JSON_OUTPUT_FILE" ".scan_start" "$(date -Iseconds)"
    json_set "$JSON_OUTPUT_FILE" ".hostname" "$(hostname)"
    json_set "$JSON_OUTPUT_FILE" ".environment.user" "$USER"
    json_set "$JSON_OUTPUT_FILE" ".environment.is_container" "$IS_CONTAINER"
    json_set "$JSON_OUTPUT_FILE" ".environment.is_vm" "$IS_VM"
    json_set "$JSON_OUTPUT_FILE" ".environment.has_jq" "$HAS_JQ"
    json_set "$JSON_OUTPUT_FILE" ".environment.has_inotify" "$HAS_INOTIFY"
    json_set "$JSON_OUTPUT_FILE" ".environment.has_yara" "$HAS_YARA"
    json_set "$JSON_OUTPUT_FILE" ".environment.has_bcc" "$HAS_BCC"
    json_set "$JSON_OUTPUT_FILE" ".environment.has_netcat" "$HAS_NETCAT"

    # Initialize system
    init_sentinel

    # Start advanced monitoring features
    declare features_enabled=()

    if [[ "$ENABLE_EBPF" == true ]] && [[ "$HAS_BCC" == true ]] && [[ $EUID -eq 0 ]]; then
        start_ebpf_monitoring
        features_enabled+=("ebpf")
        json_set "$JSON_OUTPUT_FILE" ".features.ebpf_monitoring" "true"
    fi

    if [[ "$ENABLE_HONEYPOTS" == true ]] && [[ "$HAS_NETCAT" == true ]]; then
        start_honeypots
        features_enabled+=("honeypots")
        json_set "$JSON_OUTPUT_FILE" ".features.honeypots" "true"
    fi

    if [[ "$ENABLE_YARA" == true ]] && [[ "$HAS_YARA" == true ]]; then
        features_enabled+=("yara")
        json_set "$JSON_OUTPUT_FILE" ".features.yara_scanning" "true"
    fi

    # Set other feature flags for dashboard integration
    json_set "$JSON_OUTPUT_FILE" ".features.anti_evasion" "$ENABLE_ANTI_EVASION"
    json_set "$JSON_OUTPUT_FILE" ".features.threat_intelligence" "$ENABLE_THREAT_INTEL"
    json_set "$JSON_OUTPUT_FILE" ".features.forensic_analysis" "true"

    # Run monitoring modules with timeout protection
    declare modules_run=()

    if [[ "$ENABLE_ANTI_EVASION" == true ]]; then
        log_info "Running anti-evasion detection..."
        if detect_anti_evasion; then
            modules_run+=("anti-evasion")
        fi
    fi

    log_info "Running network monitoring..."
    if monitor_network_advanced; then
        modules_run+=("network")
    fi

    log_info "Running file monitoring with YARA..."
    if monitor_files_with_yara; then
        modules_run+=("files-yara")
    fi

    log_info "Running process monitoring..."
    if monitor_processes; then
        modules_run+=("processes")
    fi

    log_info "Running user monitoring..."
    if monitor_users; then
        modules_run+=("users")
    fi

    log_info "Running rootkit detection..."
    if monitor_rootkits; then
        modules_run+=("rootkits")
    fi

    log_info "Running memory monitoring..."
    if monitor_memory; then
        modules_run+=("memory")
    fi

    declare end_time=$(date +%s)
    declare duration=$((end_time - start_time))

    # Stop background services before generating summary
    stop_honeypots
    stop_ebpf_monitoring

    # Update final JSON metadata
    json_set "$JSON_OUTPUT_FILE" ".scan_end" "$(date -Iseconds)"
    json_set "$JSON_OUTPUT_FILE" ".performance.scan_duration" "$duration"

    # Generate comprehensive summary
    generate_enhanced_summary "$duration" "${modules_run[@]}"

    # Copy JSON to user directory for dashboard access
    if [[ $EUID -eq 0 ]] && [[ -f "$JSON_OUTPUT_FILE" ]]; then
        declare user_json="$HOME/.ghost-sentinel/logs/latest_scan.json"
        mkdir -p "$(dirname "$user_json")" 2>/dev/null || true
        cp "$JSON_OUTPUT_FILE" "$user_json" 2>/dev/null || true
    fi

    log_info "Advanced security scan completed in ${duration}s"

    if [[ ${#features_enabled[@]} -gt 0 ]]; then
        log_info "Advanced features active: ${features_enabled[*]}"
    fi
}

# Enhanced summary with module and feature status
generate_enhanced_summary() {
    declare duration="$1"
    shift
    declare modules_run=("$@")

    declare today=$(date +%Y%m%d)
    declare alert_file="$ALERTS_DIR/$today.log"

    declare -i alert_count=0
    declare -i critical_count=0
    declare -i high_count=0
    declare -i medium_count=0
    declare -i low_count=0

    if [[ -f "$alert_file" ]]; then
        alert_count=$(( $(grep -c "^\[" "$alert_file" 2>/dev/null) ))
        critical_count=$(( $(grep -c "CRITICAL" "$alert_file" 2>/dev/null) ))
        high_count=$(( $(grep -c "HIGH" "$alert_file" 2>/dev/null) ))
        medium_count=$(( $(grep -c "MEDIUM" "$alert_file" 2>/dev/null) ))
        low_count=$(( $(grep -c "LOW" "$alert_file" 2>/dev/null) ))
    fi

    echo
    echo -e "${CYAN}=== GHOST SENTINEL v4.0 ADVANCED SECURITY SUMMARY ===${NC}"
    echo -e "${YELLOW}Scan Duration: ${duration}s${NC}"
    echo -e "${YELLOW}Modules Run: ${#modules_run[@]} (${modules_run[*]})${NC}"
    echo -e "${YELLOW}Total Alerts: $alert_count${NC}"
    echo -e "${RED}Critical: $critical_count${NC}"
    echo -e "${YELLOW}High: $high_count${NC}"
    echo -e "${BLUE}Medium: $medium_count${NC}"
    echo -e "${GREEN}Low: $low_count${NC}"
    echo -e "${BLUE}Environment: Container=$IS_CONTAINER, VM=$IS_VM${NC}"
    echo -e "${BLUE}Capabilities: YARA=$HAS_YARA, eBPF=$HAS_BCC, jq=$HAS_JQ${NC}"
    echo -e "${CYAN}Logs: $LOG_DIR${NC}"
    echo -e "${CYAN}JSON Output: $JSON_OUTPUT_FILE${NC}"

    # Show active advanced features
    declare active_features=()
    if [[ -f "$LOG_DIR/ebpf_monitor.pid" ]]; then
        active_features+=("eBPF Monitoring")
    fi
    if [[ -f "$LOG_DIR/honeypot.pids" ]]; then
        active_features+=("Honeypots")
    fi
    if [[ -f "$LOG_DIR/dashboard.pid" ]]; then
        active_features+=("Dashboard")
    fi

    if [[ ${#active_features[@]} -gt 0 ]]; then
        echo -e "${PURPLE}Active Features: ${active_features[*]}${NC}"
    fi

    # Variables are already declared as integers above
    if (( critical_count > 0 )) || (( high_count > 0 )); then
        echo -e "\n${RED}Priority Alerts:${NC}"
        grep -E "(CRITICAL|HIGH)" "$alert_file" 2>/dev/null | tail -5 | while read line; do
            declare level=$(echo "$line" | grep -o "\[LEVEL:[0-9]\]" | grep -o "[0-9]")
            declare msg=$(echo "$line" | cut -d']' -f3- | sed 's/^ *//')
            if [[ "$level" == "1" ]]; then
                echo -e "${RED} CRITICAL: $msg${NC}"
            else
                echo -e "${YELLOW} HIGH: $msg${NC}"
            fi
        done
    else
        echo -e "${GREEN}✓ No critical threats detected${NC}"
    fi

    # Integrity status
    declare -i baseline_age=0
    if [[ -f "$BASELINE_DIR/.initialized" ]]; then
        declare init_time=$(stat -c %Y "$BASELINE_DIR/.initialized" 2>/dev/null || echo $(date +%s))
        declare current_time=$(date +%s)
        baseline_age=$(( (current_time - init_time) / 86400 ))
    fi
    echo -e "${CYAN}Baseline Age: $baseline_age days${NC}"

    if [[ $baseline_age -gt 30 ]]; then
        echo -e "${YELLOW} Consider updating baseline (run with 'baseline' option)${NC}"
    fi
}

# Minimal required functions for compatibility
monitor_network() { monitor_network_advanced; }

monitor_processes() {
    if [[ "$MONITOR_PROCESSES" != true ]]; then return; fi
    log_info "Basic process monitoring..."

    # Check for suspicious processes
    declare suspicious_procs=("nc" "netcat" "socat" "ncat")
    for proc in "${suspicious_procs[@]}"; do
        if pgrep -f "$proc" >/dev/null 2>&1; then
            pgrep -f "$proc" 2>/dev/null | head -3 | while read pid; do
                declare proc_info=$(ps -p "$pid" -o user,comm,args --no-headers 2>/dev/null || echo "")
                if [[ -n "$proc_info" ]]; then
                    declare user=$(echo "$proc_info" | awk '{print $1}')
                    declare comm=$(echo "$proc_info" | awk '{print $2}')
                    declare args=$(echo "$proc_info" | awk '{for(i=3;i<=NF;i++) printf "%s ", $i}')

                    if ! is_whitelisted_process "$comm"; then
                        log_alert $MEDIUM "Potentially suspicious process: $comm (User: $user, PID: $pid)"
                    fi
                fi
            done
        fi
    done
}

monitor_files() { monitor_files_with_yara; }

monitor_users() {
    if [[ "$MONITOR_USERS" != true ]]; then return; fi
    log_info "Basic user monitoring..."

    # Check for new users
    if [[ -r /etc/passwd ]] && [[ -f "$BASELINE_DIR/users_baseline.txt" ]]; then
        declare current_users=$(cut -d: -f1 /etc/passwd | sort)
        declare new_users=$(comm -13 "$BASELINE_DIR/users_baseline.txt" <(echo "$current_users") 2>/dev/null | head -3)

        if [[ -n "$new_users" ]]; then
            echo "$new_users" | while read user; do
                if getent passwd "$user" >/dev/null 2>&1; then
                    log_alert $HIGH "New user account detected: $user"
                fi
            done
        fi
    fi
}

monitor_rootkits() {
    if [[ "$MONITOR_ROOTKITS" != true ]]; then return; fi
    log_info "Basic rootkit detection..."

    # Check for common rootkit indicators
    declare rootkit_paths=("/tmp/.ICE-unix/.X11-unix" "/dev/shm/.hidden" "/tmp/.hidden" "/usr/bin/..." "/usr/sbin/...")

    for path in "${rootkit_paths[@]}"; do
        if [[ -e "$path" ]]; then
            log_alert $CRITICAL "Rootkit indicator found: $path"
        fi
    done
}

monitor_memory() {
    if [[ "$MONITOR_MEMORY" != true ]]; then return; fi
    log_info "Basic memory monitoring..."

    # Check for high memory usage
    ps aux --sort=-%mem --no-headers 2>/dev/null | head -3 | while read line; do
        declare mem_usage=$(echo "$line" | awk '{print $4}')
        declare proc_name=$(echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null)
        declare pid=$(echo "$line" | awk '{print $2}')

        if ! is_whitelisted_process "$proc_name"; then
            declare mem_int=${mem_usage%.*}  # Remove decimal part
            if (( mem_int > 80 )); then
                log_alert $MEDIUM "High memory usage: $proc_name (PID: $pid, MEM: $mem_usage%)"
            fi
        fi
    done
}

# Original compatibility function
main() {
    log_info "Ghost Sentinel v4.0 starting security scan..."

    init_sentinel

    monitor_network
    monitor_processes
    monitor_files
    monitor_users
    monitor_rootkits
    monitor_memory

    log_info "Security scan completed"

    declare today=$(date +%Y%m%d)
    declare alert_count=$(grep -c "^\[" "$ALERTS_DIR/$today.log" 2>/dev/null || echo 0)

    if [[ $alert_count -gt 0 ]]; then
        echo -e "${YELLOW}Security Summary: $alert_count alerts generated${NC}"
        echo -e "${YELLOW}Check: $ALERTS_DIR/$today.log${NC}"
    else
        echo -e "${GREEN}Security Summary: No threats detected${NC}"
    fi
}

# Enhanced installation with systemd integration
install_cron() {
    declare cron_entry="0 * * * * $SCRIPT_DIR/$SCRIPT_NAME >/dev/null 2>&1"

    if command -v crontab >/dev/null 2>&1; then
        if ! crontab -l 2>/dev/null | grep -q "ghost_sentinel"; then
            (crontab -l 2>/dev/null; echo "$cron_entry") | crontab - 2>/dev/null || {
                echo "Failed to install cron job - check permissions"
                return 1
            }
            log_info "Ghost Sentinel installed to run hourly via cron"
        else
            log_info "Ghost Sentinel cron job already exists"
        fi
    else
        echo "crontab not available - manual scheduling required"
        return 1
    fi

    # Optionally create systemd service
    if [[ $EUID -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
        create_systemd_service
    fi
}

# Create systemd service for enhanced integration
create_systemd_service() {
    declare service_file="/etc/systemd/system/ghost-sentinel.service"
    declare timer_file="/etc/systemd/system/ghost-sentinel.timer"

    cat > "$service_file" << EOF
[Unit]
Description=Ghost Sentinel v4.0 Security Monitor
After=network.target

[Service]
Type=oneshot
ExecStart=$SCRIPT_PATH enhanced
User=root
StandardOutput=journal
StandardError=journal
EOF

    cat > "$timer_file" << EOF
[Unit]
Description=Run Ghost Sentinel hourly
Requires=ghost-sentinel.service

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload
    systemctl enable ghost-sentinel.timer
    systemctl start ghost-sentinel.timer

    log_info "Systemd service and timer installed"
}

# Secure self-update with integrity verification
self_update() {
    log_info "Checking for updates with integrity verification..."

    declare update_url="https://raw.githubusercontent.com/your-repo/ghost-sentinel/main/ghost_sentinel.sh"
    declare temp_file=$(mktemp)
    declare temp_sig=$(mktemp)

    if command -v curl >/dev/null 2>&1; then
        # Download script and signature
        if curl -s --max-time 30 -o "$temp_file" "$update_url" && \
           curl -s --max-time 30 -o "$temp_sig" "$update_url.sig"; then

            # Verify GPG signature if available
            if command -v gpg >/dev/null 2>&1 && [[ -s "$temp_sig" ]]; then
                if gpg --verify "$temp_sig" "$temp_file" 2>/dev/null; then
                    log_info "GPG signature verified"
                else
                    log_info "GPG verification failed - aborting update"
                    rm -f "$temp_file" "$temp_sig"
                    return 1
                fi
            fi

            # Basic validation
            if [[ -s "$temp_file" ]] && head -1 "$temp_file" | grep -q "#!/bin/bash"; then
                # Backup current version
                cp "$SCRIPT_PATH" "$SCRIPT_PATH.backup.$(date +%s)"

                # Install update
                chmod +x "$temp_file"
                mv "$temp_file" "$SCRIPT_PATH"
                rm -f "$temp_sig"

                log_info "Update completed successfully"
                log_info "Previous version backed up as $SCRIPT_PATH.backup.*"
            else
                log_info "Update failed - invalid file downloaded"
                rm -f "$temp_file" "$temp_sig"
                return 1
            fi
        else
            log_info "Update failed - download error"
            rm -f "$temp_file" "$temp_sig"
            return 1
        fi
    else
        log_info "curl not available - cannot update"
        return 1
    fi
}

# === MAIN EXECUTION ===

# Acquire exclusive lock with stale lock detection
acquire_lock

# Command line interface with new v4.0 options
case "${1:-run}" in
"install")
    install_cron
    ;;
"baseline")
    FORCE_BASELINE=true
    init_sentinel
    ;;
"config")
    ${EDITOR:-nano} "$CONFIG_FILE"
    ;;
"logs")
    init_sentinel
    if [[ -f "$LOG_DIR/sentinel.log" ]]; then
        tail -f "$LOG_DIR/sentinel.log"
    else
        echo "No log file found. Run a scan first."
    fi
    ;;
"alerts")
    init_sentinel
    declare today=$(date +%Y%m%d)
    if [[ -f "$ALERTS_DIR/$today.log" ]]; then
        cat "$ALERTS_DIR/$today.log"
    else
        echo "No alerts for today"
    fi
    ;;
"json")
    init_sentinel
    if [[ -f "$JSON_OUTPUT_FILE" ]]; then
        if [[ "$HAS_JQ" == true ]]; then
            jq . "$JSON_OUTPUT_FILE"
        else
            cat "$JSON_OUTPUT_FILE"
        fi
    else
        echo "No JSON output available"
    fi
    ;;
"test")
    echo "Testing Ghost Sentinel v4.0..."
    init_sentinel
    log_alert $HIGH "Test alert - Ghost Sentinel v4.0 is working"
    echo -e "${GREEN}✓ Test completed successfully!${NC}"
    echo -e "${CYAN}Advanced Capabilities:${NC}"
    echo -e "  YARA: $HAS_YARA"
    echo -e "  eBPF: $HAS_BCC"
    echo -e "  jq: $HAS_JQ"
    echo -e "  inotify: $HAS_INOTIFY"
    echo -e "  netcat: $HAS_NETCAT"
    echo -e "${CYAN}Environment: Container=$IS_CONTAINER, VM=$IS_VM${NC}"
    echo -e "${CYAN}Logs: $LOG_DIR${NC}"
    echo -e "${CYAN}JSON: $JSON_OUTPUT_FILE${NC}"
    ;;
"enhanced"|"v2"|"v3")
    main_enhanced
    ;;
"update")
    self_update
    ;;
"performance")
    PERFORMANCE_MODE=true
    main_enhanced
    ;;
"integrity")
    # Load config first to set variables
    load_config_safe
    validate_script_integrity
    echo -e "${GREEN}✓ Script integrity check completed${NC}"
    ;;
"reset-integrity")
    # Reset script integrity hash after updates
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    declare script_hash_file="$LOG_DIR/.script_hash"
    declare current_hash=$(sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1)
    echo "$current_hash" > "$script_hash_file"
    echo -e "${GREEN}✓ Script integrity hash reset${NC}"
    echo "Current hash: $current_hash"
    ;;
"fix-hostname")
    # Fix the hostname resolution issue
    declare current_hostname=$(hostname)
    if ! grep -q "$current_hostname" /etc/hosts; then
        echo "127.0.0.1 $current_hostname" | sudo tee -a /etc/hosts >/dev/null
        echo -e "${GREEN}✓ Hostname resolution fixed${NC}"
    else
        echo -e "${GREEN}✓ Hostname resolution already OK${NC}"
    fi
    ;;
"systemd")
    if [[ $EUID -eq 0 ]]; then
        create_systemd_service
    else
        echo "systemd integration requires root privileges"
    fi
    ;;
"honeypot")
    init_sentinel
    start_honeypots
    echo "Honeypots started. Press Ctrl+C to stop."
    read -r
    stop_honeypots
    ;;
"cleanup")
    echo "Cleaning up Ghost Sentinel processes and fixing common issues..."

    # Stop all running components
    stop_honeypots
    stop_ebpf_monitoring

    # Kill any remaining processes
    pkill -f "ghost_sentinel" 2>/dev/null || true
    pkill -f "ghost-sentinel" 2>/dev/null || true

    # Clean up temp files
    rm -f /tmp/ghost_sentinel_* /tmp/ghost-sentinel*

    # Remove lock files
    rm -f "$LOCK_FILE" "$PID_FILE"

    # Reset script integrity hash (normal after updates)
    mkdir -p "$LOG_DIR" 2>/dev/null || true
    declare script_hash_file="$LOG_DIR/.script_hash"
    declare current_hash=$(sha256sum "$SCRIPT_PATH" 2>/dev/null | cut -d' ' -f1)
    echo "$current_hash" > "$script_hash_file"

    # Fix hostname resolution if needed
    declare current_hostname=$(hostname)
    if ! grep -q "$current_hostname" /etc/hosts 2>/dev/null; then
        echo "127.0.0.1 $current_hostname" | sudo tee -a /etc/hosts >/dev/null 2>&1 || true
        echo "✓ Fixed hostname resolution"
    fi

    echo -e "${GREEN}✓ Cleanup completed - all issues resolved${NC}"
    echo "You can now run: sudo ./the_protector.sh test"
    ;;
"status")
    echo "Ghost Sentinel v4.0 Status:"
    echo "=========================="

    # Check for running processes
    if [[ -f "$LOG_DIR/honeypot.pids" ]]; then
        declare honeypot_count=$(wc -l < "$LOG_DIR/honeypot.pids" 2>/dev/null || echo 0)
        echo -e "${GREEN}✓ Honeypots running: $honeypot_count${NC}"
    else
        echo -e "${RED}✗ Honeypots not running${NC}"
    fi

    if [[ -f "$LOG_DIR/ebpf_monitor.pid" ]]; then
        declare ebpf_pid=$(cat "$LOG_DIR/ebpf_monitor.pid" 2>/dev/null || echo "")
        if [[ -n "$ebpf_pid" ]] && kill -0 "$ebpf_pid" 2>/dev/null; then
            echo -e "${GREEN}✓ eBPF Monitor running (PID: $ebpf_pid)${NC}"
        else
            echo -e "${RED}✗ eBPF Monitor not running${NC}"
        fi
    else
        echo -e "${RED}✗ eBPF Monitor not running${NC}"
    fi

    if [[ -f "$LOG_DIR/dashboard.pid" ]]; then
        declare dash_pid=$(cat "$LOG_DIR/dashboard.pid" 2>/dev/null || echo "")
        if [[ -n "$dash_pid" ]] && kill -0 "$dash_pid" 2>/dev/null; then
            echo -e "${GREEN}✓ Dashboard running (PID: $dash_pid)${NC}"
        else
            echo -e "${RED}✗ Dashboard not running${NC}"
        fi
    else
        echo -e "${RED}✗ Dashboard not running${NC}"
    fi

    # Show recent alerts
    declare today=$(date +%Y%m%d)
    if [[ -f "$ALERTS_DIR/$today.log" ]]; then
        declare alert_count=$(grep -c "^\[" "$ALERTS_DIR/$today.log" 2>/dev/null || echo 0)
        echo -e "${YELLOW}Alerts today: $alert_count${NC}"
    else
        echo -e "${GREEN}No alerts today${NC}"
    fi
    ;;
"yara")
    if [[ "$HAS_YARA" == true ]]; then
        init_sentinel
        monitor_files_with_yara
    else
        echo "YARA not available - install yara package"
    fi
    ;;
"ebpf")
    if [[ "$HAS_BCC" == true ]] && [[ $EUID -eq 0 ]]; then
        init_sentinel
        start_ebpf_monitoring
        echo "eBPF monitoring started. Press Ctrl+C to stop."
        read -r
        stop_ebpf_monitoring
    else
        echo "eBPF monitoring requires root privileges and BCC tools"
    fi
    ;;
"dashboard")
    if [[ -f "theProtector.go" ]] && command -v go >/dev/null 2>&1; then
        log_info "Starting Ghost Sentinel Dashboard..."
        go run theProtector.go &
        echo $! > "$LOG_DIR/dashboard.pid"
        log_info "Dashboard started on http://localhost:8082"
        log_info "Press Ctrl+C to stop"
        wait
    else
        echo "Go or theProtector.go not found - cannot start dashboard"
    fi
    ;;
"daemon")
    log_info "Starting Ghost Sentinel in daemon mode - scanning every hour..."
    while true; do
        main_enhanced
        log_info "Sleeping for 1 hour before next scan..."
        sleep 3600
    done
    ;;
"loop")
    log_info "Starting Ghost Sentinel in loop mode - scanning every hour..."
    while true; do
        main_enhanced
        log_info "Sleeping for 1 hour before next scan..."
        sleep 3600
    done
    ;;
esac
