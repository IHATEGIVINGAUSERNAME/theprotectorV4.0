#!/usr/bin/env bash

set -euo pipefail

VERBOSE=false
if [[ " $* " == *" --verbose "* ]]; then
    set -x
    VERBOSE=true
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
LOCK_FILE="/tmp/ghost-sentinel-$USER.lock"
PID_FILE="/tmp/ghost-sentinel-$USER.pid"

if [[ $EUID -eq 0 ]]; then
    LOG_DIR="/var/log/ghost-sentinel"
    BACKUP_DIR="/var/backups/ghost-sentinel"
else
    LOG_DIR="$HOME/.ghost-sentinel/logs"
    BACKUP_DIR="$HOME/.ghost-sentinel/backups"
fi

CONFIG_FILE="$SCRIPT_DIR/sentinel.conf"
BASELINE_DIR="$LOG_DIR/baseline"
ALERTS_DIR="$LOG_DIR/alerts"
QUARANTINE_DIR="$LOG_DIR/quarantine"
JSON_OUTPUT_FILE="$LOG_DIR/latest_scan.json"
THREAT_INTEL_DIR="$LOG_DIR/threat_intel"
YARA_RULES_DIR="$LOG_DIR/yara_rules"
SCRIPTS_DIR="$LOG_DIR/scripts"
HONEYPOT_LOG="$LOG_DIR/honeypot.log"
EBPF_LOG="$LOG_DIR/ebpf_events.log"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'
CRITICAL=1
HIGH=2
MEDIUM=3
LOW=4

MAX_FIND_DEPTH=2
SCAN_TIMEOUT=180
PARALLEL_JOBS=2
THREAT_INTEL_UPDATE_HOURS=1
HONEYPOT_PORTS=("2222" "8080" "23" "21" "3389")

IS_CONTAINER=false
IS_VM=false
IS_DEBIAN=false
IS_FEDORA=false
IS_NIXOS=false
HAS_JQ=false
HAS_INOTIFY=false
HAS_YARA=false
HAS_BCC=false
HAS_NETCAT=false
NETCAT_BIN="nc"

cmd() {
    command -v "$1" >/dev/null 2>&1
}

cleanup() {
    declare exit_code=$?

    stop_honeypots

    stop_ebpf_monitoring

    rm -f "$LOCK_FILE" "$PID_FILE" 2>/dev/null || true

    exit $exit_code
}
trap cleanup EXIT INT TERM

acquire_lock() {

    if [[ -f "$LOCK_FILE" ]]; then
        declare lock_pid=""
        if [[ -f "$PID_FILE" ]]; then
            lock_pid=$(cat "$PID_FILE" 2>/dev/null || echo "")
        fi


        if [[ -n "$lock_pid" ]] && kill -0 "$lock_pid" 2>/dev/null; then
            echo "Another instance is running (PID: $lock_pid). Exiting."
            exit 1
        else
       
            rm -f "$LOCK_FILE" "$PID_FILE" 2>/dev/null || true
        fi
    fi

  
    if cmd flock; then
        exec 200>"$LOCK_FILE"
        if ! flock -n 200; then
            echo "Failed to acquire lock. Another instance may be running."
            exit 1
        fi
    else
        echo $$ > "$LOCK_FILE"
    fi


    echo $$ > "$PID_FILE"
}


check_dependencies() {
    # Check for jq
    if cmd jq; then
        HAS_JQ=true
    fi

    # Check for inotify tools
    if cmd inotifywait; then
        HAS_INOTIFY=true
    fi

    # Check for YARA
    if cmd yara; then
        HAS_YARA=true
    fi

    # Check for eBPF/BCC tools - fixing for correct path
    if cmd bpftrace || [[ -d /usr/share/bcc/tools ]] || cmd execsnoop-bpfcc; then
    HAS_BCC=true
    fi


    if cmd nc; then
        HAS_NETCAT=true
        [[ "$VERBOSE" == true ]] && log_info "Detected 'nc' executable"
    elif cmd netcat; then
        HAS_NETCAT=true
        NETCAT_BIN="netcat"
        [[ "$VERBOSE" == true ]] && log_info "Detected 'netcat' executable"
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


detect_environment() {

    if [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] || grep -q "docker\|lxc\|containerd" /proc/1/cgroup 2>/dev/null; then
        IS_CONTAINER=true
    fi

    if cmd systemd-detect-virt; then
        if systemd-detect-virt -q; then
            IS_VM=true
        fi
    elif cmd dmidecode && [[ $EUID -eq 0 ]]; then
        declare vendor=$(dmidecode -s system-product-name 2>/dev/null | tr '[:upper:]' '[:lower:]')
        if [[ "$vendor" =~ (vmware|virtualbox|qemu|kvm|xen) ]]; then
            IS_VM=true
        fi
    fi

    # Check what system
    grep -qi "debian" /etc/os-release &>/dev/null && IS_DEBIAN=true

    
    grep -qi "fedora" /etc/os-release &>/dev/null && IS_FEDORA=true

    grep -qi "nixos" /etc/os-release &>/dev/null && IS_NIXOS=true

    true # return true in case os is not recognised to prevent triggering set -e
}


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
            echo "  sudo ./theprotector.sh reset-integrity"
            echo ""
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
        fi
    fi


    echo "$current_hash" > "$script_hash_file"
}

json_set() {
    declare file="$1"
    declare key="$2"
    declare value="$3"

    if [[ "$HAS_JQ" == true ]]; then
        declare tmp_file=$(mktemp)
        jq "$key = \"$value\"" "$file" > "$tmp_file" 2>/dev/null && mv "$tmp_file" "$file"
    else
      
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
    
        echo "{\"level\": $level, \"message\": \"$message\", \"timestamp\": \"$timestamp\"}" >> "$LOG_DIR/alerts.jsonl"
    fi
}


init_yara_rules() {
    if [[ "$HAS_YARA" != true ]]; then
        return
    fi

    mkdir -p "$YARA_RULES_DIR"

 
    cat > "$YARA_RULES_DIR/malware_detection.yar" << 'EOF'
import "pe"
import "elf"
import "hash"

rule Enterprise_Malware_Detection {
    meta:
        description = "Enterprise-grade malware detection with multiple indicators"
        author = "Ghost Sentinel"
        severity = "high"
        category = "malware"
        tags = "enterprise,malware,detection"
        minimum_yara = "3.8.0"
    strings:
        // Advanced obfuscation techniques
        $obfuscation1 = { 58 6F 62 66 75 73 63 61 74 65 } // :obfuscate
        $obfuscation2 = /\b(eval|base64_decode|gzinflate|str_rot13)\s*\(/ nocase
        $obfuscation3 = { 5B 27 5D 2E 5B 27 5D } // [''].[''] pattern

        // Shellcode patterns
        $shellcode1 = { B8 ?? ?? ?? ?? C1 C8 08 C1 C8 08 C1 C8 08 C1 C8 08 } // mov eax, imm32; ror eax, 8 (4x)
        $shellcode2 = { 31 C0 50 68 } // xor eax,eax; push eax; push imm32
        $shellcode3 = { 6A 0B 58 99 52 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 89 C1 89 C2 CD 80 } // Linux execve shell

        // Memory manipulation
        $memory1 = { 64 A1 30 00 00 00 } // mov eax, fs:[0x30] (PEB access)
        $memory2 = { 8B 40 0C 8B 40 1C 8B 00 8B 00 8B 40 08 } // PEB->Ldr->InLoadOrderModuleList traversal

        // Anti-analysis techniques
        $anti_analysis1 = { 0F 31 } // rdtsc
        $anti_analysis2 = { 0F A2 } // cpuid
        $anti_analysis3 = /\b(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString)\b/ nocase

    condition:
        (2 of ($obfuscation*)) or
        (any of ($shellcode*)) or
        (2 of ($memory*)) or
        (2 of ($anti_analysis*)) or
        (filesize < 10MB and (
            pe.is_pe and (
                pe.sections[0].name == ".text" and
                pe.sections[0].raw_data_size > 100KB
            )
        ))
}

rule Advanced_Persistence_Mechanisms {
    meta:
        description = "Advanced persistence mechanism detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "persistence"
        tags = "enterprise,persistence,apt"
    strings:
        // Registry persistence
        $reg1 = /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run/ nocase
        $reg2 = /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce/ nocase
        $reg3 = /SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run/ nocase

        // Service creation
        $service1 = /\b(sc\.exe|net\.exe|powershell)\s+(create|start)/ nocase
        $service2 = /New-Service\s+-/ nocase

        // Scheduled tasks
        $task1 = /\b(schtasks|schtasks\.exe)\s+/ nocase
        $task2 = /at\.exe\s+/ nocase

        // Startup folder
        $startup1 = /AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/ nocase
        $startup2 = /ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp/ nocase

        // DLL hijacking
        $dll1 = /KnownDLLs/ nocase
        $dll2 = /AppInit_DLLs/ nocase

        // WMI persistence
        $wmi1 = /winmgmts:\\root\\subscription/ nocase
        $wmi2 = /ActiveScriptEventConsumer/ nocase

    condition:
        any of them
}

rule Enterprise_Crypto_Mining {
    meta:
        description = "Enterprise crypto mining detection with wallet patterns"
        author = "Ghost Sentinel"
        severity = "high"
        category = "cryptomining"
        tags = "enterprise,miner,crypto"
    strings:
        // Mining pool domains
        $pool1 = "stratum+tcp://" nocase
        $pool2 = "stratum+ssl://" nocase
        $pool3 = /\.mining\.pool/ nocase
        $pool4 = /pool\..*\.com/ nocase

        // Mining software
        $miner1 = "xmrig" nocase
        $miner2 = "cpuminer" nocase
        $miner3 = "ethminer" nocase
        $miner4 = "cgminer" nocase
        $miner5 = "bfgminer" nocase

        // Wallet addresses (Bitcoin, Monero, Ethereum patterns)
        $wallet_btc = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/
        $wallet_xmr = /[48][0-9AB][123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]{93}/
        $wallet_eth = /0x[a-fA-F0-9]{40}/

        // Mining algorithms
        $algo1 = /\b(cryptonight|randomx|kawpow|ethash)\b/ nocase
        $algo2 = /\b(scrypt|sha256|x11|equihash)\b/ nocase

        // CPU/GPU mining commands
        $cmd1 = /--cpu-priority/ nocase
        $cmd2 = /--threads/ nocase
        $cmd3 = /--gpu/ nocase

    condition:
        (any of ($miner*)) or
        (2 of ($pool*)) or
        (any of ($wallet*)) or
        (2 of ($algo*)) or
        (3 of ($cmd*))
}

rule APT_Lateral_Movement_Advanced {
    meta:
        description = "Advanced APT lateral movement detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "apt"
        tags = "enterprise,apt,lateral_movement"
    strings:
        // Advanced tools
        $tool1 = "mimikatz" nocase
        $tool2 = "bloodhound" nocase
        $tool3 = "sharphound" nocase
        $tool4 = "cobaltstrike" nocase
        $tool5 = "empire" nocase
        $tool6 = "metasploit" nocase

        // PowerShell Empire/Cobalt Strike indicators
        $ps1 = /\bIEX\s*\(/ nocase
        $ps2 = /New-Object\s+Net\.WebClient/ nocase
        $ps3 = /DownloadString\s*\(/ nocase
        $ps4 = /Invoke-Expression/ nocase

        // Living off the land
        $lotl1 = /bitsadmin\s+/ nocase
        $lotl2 = /certutil\s+-urlcache/ nocase
        $lotl3 = /mshta\s+/ nocase
        $lotl4 = /rundll32\s+/ nocase

        // Network reconnaissance
        $recon1 = /nmap\s+/ nocase
        $recon2 = /masscan\s+/ nocase
        $recon3 = /zmap\s+/ nocase

        // Exfiltration
        $exfil1 = /rclone\s+/ nocase
        $exfil2 = /megatools\s+/ nocase
        $exfil3 = /scp\s+/ nocase

    condition:
        (any of ($tool*)) or
        (3 of ($ps*)) or
        (2 of ($lotl*)) or
        (any of ($recon*)) or
        (2 of ($exfil*))
}

rule Enterprise_Ransomware_Indicators {
    meta:
        description = "Enterprise ransomware detection patterns"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "ransomware"
        tags = "enterprise,ransomware,encryption"
    strings:
   
        $encrypt1 = /vssadmin\s+delete\s+shadows/ nocase
        $encrypt2 = /wbadmin\s+delete\s+backup/ nocase
        $encrypt3 = /bcdedit\s+\/set\s+{default}\s+recoveryenabled\s+no/ nocase

      
        $ext1 = ".encrypted" nocase
        $ext2 = ".locked" nocase
        $ext3 = ".crypto" nocase
        $ext4 = ".crypt" nocase
        $ext5 = ".readme" nocase

        // Ransom notes
        $note1 = "your files have been encrypted" nocase
        $note2 = "pay bitcoin" nocase
        $note3 = "decrypt your files" nocase
        $note4 = "bitcoin wallet" nocase

      
        $family1 = "wannacry" nocase
        $family2 = "ryuk" nocase
        $family3 = "conti" nocase
        $family4 = "lockbit" nocase

       
        $crypto1 = /AES\s*256/ nocase
        $crypto2 = /RSA\s*2048/ nocase

    condition:
        (2 of ($encrypt*)) or
        (3 of ($ext*)) or
        (2 of ($note*)) or
        (any of ($family*)) or
        (2 of ($crypto*))
}

rule Enterprise_Webshell_Detection {
    meta:
        description = "Advanced webshell detection for enterprise environments"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "webshell"
        tags = "enterprise,webshell,backdoor"
    strings:
       
        $php1 = /(\$_(GET|POST|REQUEST)\s*\[.*?\]\s*\(\s*\$_(GET|POST|REQUEST)\s*\[.*?\]\s*\))/ nocase
        $php2 = /eval\s*\(\s*base64_decode\s*\(/ nocase
        $php3 = /system\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $php4 = /shell_exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $php5 = /passthru\s*\(\s*\$_(GET|POST|REQUEST)/ nocase
        $php6 = /exec\s*\(\s*\$_(GET|POST|REQUEST)/ nocase

        
        $asp1 = /eval\s*\(\s*request/ nocase
        $asp2 = /execute\s*\(\s*request/ nocase
        $asp3 = /response\.write\s*\(\s*server\.createobject/ nocase

       
        $jsp1 = /Runtime\.getRuntime\(\)\.exec/ nocase
        $jsp2 = /ProcessBuilder/ nocase

        
        $generic1 = /password\s*=\s*['"]*admin['"]*/ nocase
        $generic2 = /cmd\s*=\s*['"]*shell['"]*/ nocase
        $generic3 = /upload\s*=\s*['"]*file['"]*/ nocase

   
        $obfuscated1 = /\\x65\\x76\\x61\\x6c/ nocase // \x65\x76\x61\x6c = eval
        $obfuscated2 = /\\x73\\x79\\x73\\x74\\x65\\x6d/ nocase // \x73\x79\x73\x74\x65\x6d = system

    condition:
        (3 of ($php*)) or
        (2 of ($asp*)) or
        (any of ($jsp*)) or
        (3 of ($generic*)) or
        (2 of ($obfuscated*))
}

rule Enterprise_Rootkit_Detection {
    meta:
        description = "Enterprise rootkit and kernel malware detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "rootkit"
        tags = "enterprise,rootkit,kernel"
    strings:
        // Kernel module manipulation
        $kernel1 = /insmod\s+/ nocase
        $kernel2 = /rmmod\s+/ nocase
        $kernel3 = /modprobe\s+/ nocase

        // System call hooking
        $syscall1 = "sys_call_table" nocase
        $syscall2 = "syscall_hook" nocase
        $syscall3 = "ftrace" nocase

        // Process hiding
        $hide1 = "hide_process" nocase
        $hide2 = "rootkit" nocase
        $hide3 = "rk_" nocase

        // DKOM (Direct Kernel Object Manipulation)
        $dkom1 = "EPROCESS" nocase
        $dkom2 = "KTHREAD" nocase
        $dkom3 = "ActiveProcessLinks" nocase

        // Known rootkit strings
        $known1 = "suckit" nocase
        $known2 = "phalanx" nocase
        $known3 = "knark" nocase
        $known4 = "adore" nocase

    condition:
        (2 of ($kernel*)) or
        (2 of ($syscall*)) or
        (2 of ($hide*)) or
        (2 of ($dkom*)) or
        (any of ($known*))
}

rule Enterprise_Data_Exfiltration {
    meta:
        description = "Advanced data exfiltration detection"
        author = "Ghost Sentinel"
        severity = "high"
        category = "exfiltration"
        tags = "enterprise,exfiltration,data_theft"
    strings:
        // Cloud storage exfiltration
        $cloud1 = /aws\s+s3\s+cp/ nocase
        $cloud2 = /azcopy\s+/ nocase
        $cloud3 = /gsutil\s+cp/ nocase
        $cloud4 = /rclone\s+/ nocase

        // DNS exfiltration
        $dns1 = /nslookup\s+/ nocase
        $dns2 = /dig\s+/ nocase
        $dns3 = /dns2tcp/ nocase

        // ICMP exfiltration
        $icmp1 = /ping\s+-p/ nocase
        $icmp2 = /hping3/ nocase

        // HTTP exfiltration
        $http1 = /curl\s+-F/ nocase
        $http2 = /wget\s+--post-file/ nocase
        $http3 = /python.*requests/ nocase

        // FTP exfiltration
        $ftp1 = /ftp\s+/ nocase
        $ftp2 = /lftp\s+/ nocase
        $ftp3 = /ncftp/ nocase

        // Email exfiltration
        $email1 = /sendmail/ nocase
        $email2 = /mail\s+/ nocase
        $email3 = /mutt\s+/ nocase

        // Large file operations
        $large1 = /dd\s+if=.*bs=.*count/ nocase
        $large2 = /tar\s+.*\|\s+(nc|netcat)/ nocase

    condition:
        (any of ($cloud*)) or
        (2 of ($dns*)) or
        (any of ($icmp*)) or
        (2 of ($http*)) or
        (2 of ($ftp*)) or
        (2 of ($email*)) or
        (any of ($large*))
}

rule Enterprise_Credential_Theft {
    meta:
        description = "Enterprise credential theft and access detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "credentials"
        tags = "enterprise,credentials,access"
    strings:
        // Password dumping
        $pwd1 = "mimikatz" nocase
        $pwd2 = "sekurlsa::logonpasswords" nocase
        $pwd3 = "lsadump::sam" nocase
        $pwd4 = "lsadump::secrets" nocase

        // Keylogging
        $keylog1 = "keylogger" nocase
        $keylog2 = "GetAsyncKeyState" nocase
        $keylog3 = "SetWindowsHookEx" nocase

        // Browser credential theft
        $browser1 = "Chrome" nocase
        $browser2 = "Login Data" nocase
        $browser3 = "cookies.sqlite" nocase

        // SSH key theft
        $ssh1 = "id_rsa" nocase
        $ssh2 = "authorized_keys" nocase
        $ssh3 = ".ssh" nocase

        // RDP credential theft
        $rdp1 = "rdp" nocase
        $rdp2 = "mstsc" nocase
        $rdp3 = "termsrv" nocase

        // Database credential theft
        $db1 = "mysql" nocase
        $db2 = "postgresql" nocase
        $db3 = "oracle" nocase
        $db4 = "config" nocase

    condition:
        (2 of ($pwd*)) or
        (2 of ($keylog*)) or
        (3 of ($browser*)) or
        (2 of ($ssh*)) or
        (2 of ($rdp*)) or
        (3 of ($db*))
}
EOF

    # Create enterprise-grade APT and advanced threat indicators
    cat > "$YARA_RULES_DIR/apt_indicators.yar" << 'EOF'
rule APT_Lateral_Movement_Enterprise {
    meta:
        description = "Enterprise APT lateral movement detection with advanced patterns"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "apt"
        tags = "enterprise,apt,lateral_movement,advanced"
        minimum_yara = "3.8.0"
    strings:
        // Advanced persistent threat tools
        $apt_tool1 = "mimikatz" nocase
        $apt_tool2 = "bloodhound" nocase
        $apt_tool3 = "sharphound" nocase
        $apt_tool4 = "cobaltstrike" nocase
        $apt_tool5 = "empire" nocase
        $apt_tool6 = "metasploit" nocase
        $apt_tool7 = "powersploit" nocase
        $apt_tool8 = "nishang" nocase

        // PowerShell Empire indicators
        $empire1 = /\bIEX\s*\(\s*New-Object\s+Net\.WebClient/ nocase
        $empire2 = /DownloadString\s*\(\s*['"]http/ nocase
        $empire3 = /Invoke-Expression\s*\(\s*\$/ nocase

        // Cobalt Strike beacons
        $beacon1 = { 41 41 41 41 41 41 41 41 } // AAAAAAAA pattern
        $beacon2 = { 42 42 42 42 42 42 42 42 } // ******** pattern
        $beacon3 = /%2f%2f%2b%2f/ nocase // //+/ encoded

        // Living off the land binaries
        $lotl1 = /bitsadmin\s+\/transfer/ nocase
        $lotl2 = /certutil\s+-urlcache\s+-split\s+-f/ nocase
        $lotl3 = /mshta\s+javascript:/ nocase
        $lotl4 = /rundll32\s+javascript:/ nocase
        $lotl5 = /regsvr32\s+\/s\s+\/n\s+\/u\s+/ nocase

        // Advanced reconnaissance
        $recon1 = /nmap\s+-sS\s+-p-/ nocase
        $recon2 = /masscan\s+/ nocase
        $recon3 = /zmap\s+/ nocase
        $recon4 = /nuclei\s+/ nocase

        // Fileless malware indicators
        $fileless1 = /powershell\s+-nop\s+-exec\s+bypass/ nocase
        $fileless2 = /wmic\s+process\s+call\s+create/ nocase
        $fileless3 = /msbuild\s+\/nologo/ nocase

        // Memory-only malware
        $memory1 = /reflective\s+loader/ nocase
        $memory2 = /process\s+hollowing/ nocase
        $memory3 = /atom\s+bombing/ nocase

    condition:
        (any of ($apt_tool*)) or
        (2 of ($empire*)) or
        (any of ($beacon*)) or
        (2 of ($lotl*)) or
        (any of ($recon*)) or
        (2 of ($fileless*)) or
        (any of ($memory*))
}

rule Enterprise_Command_and_Control {
    meta:
        description = "Enterprise C2 communication detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "c2"
        tags = "enterprise,c2,command_control"
    strings:
        // DNS tunneling
        $dns1 = /dnscat/ nocase
        $dns2 = /iodine/ nocase
        $dns3 = /dns2tcp/ nocase

        // HTTP C2
        $http1 = /User-Agent:\s*Mozilla\/5\.0\s+\(compatible;\s*MSIE\s+9\.0/ nocase
        $http2 = /Content-Type:\s*application\/octet-stream/ nocase
        $http3 = /X-Requested-With:\s*XMLHttpRequest/ nocase

        // HTTPS C2 with suspicious patterns
        $https1 = /sslstrip/ nocase
        $https2 = /bettercap/ nocase

        // ICMP C2
        $icmp1 = /icmptunnel/ nocase
        $icmp2 = /hans/ nocase

        // Custom protocol C2
        $custom1 = /custom\s+protocol/ nocase
        $custom2 = /protocol\s+obfuscation/ nocase

        // C2 framework signatures
        $framework1 = "covenant" nocase
        $framework2 = "brute ratel" nocase
        $framework3 = "sliver" nocase
        $framework4 = "havoc" nocase

    condition:
        (any of ($dns*)) or
        (3 of ($http*)) or
        (any of ($https*)) or
        (any of ($icmp*)) or
        (any of ($custom*)) or
        (any of ($framework*))
}

rule Enterprise_Zero_Day_Exploits {
    meta:
        description = "Zero-day and N-day exploit detection patterns"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "exploit"
        tags = "enterprise,exploit,zero_day"
    strings:
        // Common vulnerability exploitation
        $cve1 = /eternalblue/i nocase
        $cve2 = /wannacry/i nocase
        $cve3 = /notpetya/i nocase
        $cve4 = /badrabbit/i nocase

        // Exploit frameworks
        $framework1 = /metasploit/i nocase
        $framework2 = /exploit-db/i nocase
        $framework3 = /rapid7/i nocase

        // Shellcode patterns
        $shellcode1 = { 31 C0 50 68 2F 2F 73 68 68 2F 62 69 6E 89 E3 50 53 89 E1 31 D2 B0 0B CD 80 } // Linux x86 execve
        $shellcode2 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 8B 52 0C 8B 52 14 8B 72 28 0F B7 4A 26 31 FF 31 C0 AC 3C 61 7C 02 2C 20 C1 CF 0D 01 C7 E2 F0 52 57 8B 52 10 8B 42 3C 01 D0 8B 40 78 85 C0 74 4A 01 D0 50 8B 48 18 8B 58 20 01 D3 E3 3C 49 8B 34 8B 01 D6 31 FF 31 C0 AC C1 CF 0D 01 C7 38 E0 75 F4 03 7D F8 3B 7D 24 75 E2 58 8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3 8B 04 8B 01 D0 89 44 24 24 5B 5B 61 59 5A 51 FF E0 58 5F 5A 8B 12 EB 86 } // Meterpreter

        // Heap spray patterns
        $heapspray1 = { 0C 0C 0C 0C } // NOP sled
        $heapspray2 = { 90 90 90 90 } // NOP sled

        // ROP gadgets
        $rop1 = { C3 } // ret
        $rop2 = { C2 ?? ?? } // ret n
        $rop3 = { FF E4 } // jmp esp

    condition:
        (any of ($cve*)) or
        (any of ($framework*)) or
        (any of ($shellcode*)) or
        (2 of ($heapspray*)) or
        (3 of ($rop*))
}

rule Enterprise_Insider_Threat {
    meta:
        description = "Insider threat and data theft detection"
        author = "Ghost Sentinel"
        severity = "high"
        category = "insider"
        tags = "enterprise,insider,data_theft"
    strings:
       
        $exfil1 = /rclone\s+/ nocase
        $exfil2 = /megatools\s+/ nocase
        $exfil3 = /rsync\s+/ nocase
        $exfil4 = /scp\s+/ nocase

     
        $archive1 = /tar\s+czf\s+/ nocase
        $archive2 = /zip\s+-r\s+/ nocase
        $archive3 = /7z\s+a\s+/ nocase

   
        $large1 = /dd\s+if=.*of=.*bs=/ nocase
        $large2 = /cp\s+.*\/dev\/null/ nocase

     
        $usb1 = /\/dev\/sd[a-z]/ nocase
        $usb2 = /\/media\// nocase
        $usb3 = /\/mnt\// nocase

        
        $cloud1 = /aws\s+s3\s+sync/ nocase
        $cloud2 = /az\s+storage\s+blob\s+upload/ nocase
        $cloud3 = /gsutil\s+rsync/ nocase

    
        $email1 = /mutt\s+-a/ nocase
        $email2 = /mail\s+-a/ nocase

    condition:
        (2 of ($exfil*)) or
        (2 of ($archive*)) or
        (any of ($large*)) or
        (2 of ($usb*)) or
        (any of ($cloud*)) or
        (any of ($email*))
}

rule Enterprise_Container_Escape {
    meta:
        description = "Container escape and privilege escalation detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "container"
        tags = "enterprise,container,escape,privilege"
    strings:
        // Docker escape techniques
        $docker1 = /docker\.sock/ nocase
        $docker2 = /var\/run\/docker\.sock/ nocase
        $docker3 = /docker\s+run\s+--privileged/ nocase

        // Kubernetes escape
        $k8s1 = /kubectl\s+exec/ nocase
        $k8s2 = /kubelet/ nocase
        $k8s3 = /serviceaccount/ nocase

        // Mount namespace escape
        $mount1 = /\/proc\/1\/ns/ nocase
        $mount2 = /setns/ nocase
        $mount3 = /unshare/ nocase

        // Capability abuse
        $cap1 = /CAP_SYS_ADMIN/ nocase
        $cap2 = /CAP_SYS_PTRACE/ nocase
        $cap3 = /CAP_DAC_OVERRIDE/ nocase

        // Device access
        $device1 = /\/dev\/mem/ nocase
        $device2 = /\/dev\/kmem/ nocase
        $device3 = /\/proc\/kcore/ nocase

    condition:
        (2 of ($docker*)) or
        (2 of ($k8s*)) or
        (2 of ($mount*)) or
        (2 of ($cap*)) or
        (any of ($device*))
}

rule Enterprise_Supply_Chain_Attack {
    meta:
        description = "Supply chain attack detection"
        author = "Ghost Sentinel"
        severity = "critical"
        category = "supply_chain"
        tags = "enterprise,supply_chain,dependency"
    strings:
        // Malicious packages
        $package1 = /solarwinds/i nocase
        $package2 = /ccleaner/i nocase
        $package3 = /notepad\+\+.*installer/i nocase

        // Dependency confusion
        $dep1 = /npm\s+install\s+.*@/ nocase
        $dep2 = /pip\s+install\s+.*==/ nocase
        $dep3 = /gem\s+install\s+.*-/ nocase

        // Malicious registries
        $registry1 = /registry\.yarnpkg\.com/ nocase
        $registry2 = /registry\.npmjs\.org/ nocase
        $registry3 = /pypi\.org/ nocase

        // Code injection in dependencies
        $inject1 = /postinstall.*script/ nocase
        $inject2 = /preinstall.*script/ nocase

        // Typosquatting
        $typo1 = /cross-env/i nocase
        $typo2 = /crossenv/i nocase
        $typo3 = /request/i nocase
        $typo4 = /reques/i nocase

    condition:
        (any of ($package*)) or
        (2 of ($dep*)) or
        (2 of ($registry*)) or
        (any of ($inject*)) or
        (2 of ($typo*))
}
EOF

    log_info "YARA rules initialized for advanced malware detection"
}

# eBPF-based monitoring
start_ebpf_monitoring() {
    if [[ "$HAS_BCC" != true ]] || [[ $EUID -ne 0 ]]; then
        log_info "eBPF monitoring requires root and BCC tools - skipping"
        return
    fi

    log_info "Starting enterprise eBPF-based kernel monitoring..."

    # Create comprehensive eBPF monitoring script
    cat > "$SCRIPTS_DIR/ghost_sentinel_ebpf_monitor.py" << 'EOF'

#!/usr/bin/env python3
import sys
import time
import json
import threading
from datetime import datetime
from bcc import BPF
from collections import defaultdict
import socket
import struct


class EnterpriseEBPFMonitor:
    def __init__(self):
        self.alerts = []
        self.stats = defaultdict(int)
        self.suspicious_patterns = {
            'exec': [
                b'nc', b'netcat', b'socat', b'/dev/tcp', b'python -c', b'perl -e',
                b'bash -i', b'sh -i', b'wget', b'curl', b'base64', b'nmap',
                b'masscan', b'metasploit', b'xmrig', b'cpuminer'
            ],
            'network': [
                b'127.0.0.1', b'0.0.0.0', b'4444', b'1337', b'6667', b'31337'
            ],
            'file': [
                b'/etc/passwd', b'/etc/shadow', b'/etc/sudoers', b'/root/.ssh',
                b'/home/*/.ssh', b'/etc/crontab', b'/etc/rc.local'
            ]
        }

    def log_alert(self, alert_type, severity, message, data=None):
        """logging with structured data"""
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': alert_type,
            'severity': severity,
            'message': message,
            'data': data or {},
            'hostname': socket.gethostname(),
            'sensor': 'ebpf_monitor'
        }

        self.alerts.append(alert)
        self.stats[f'{alert_type}_{severity}'] += 1

        # Write to structured log
        with open('/var/log/ghost-sentinel/ebpf_alerts.jsonl', 'a') as f:
            f.write(json.dumps(alert) + '\n')

        # Immediate alerting for critical events
        if severity == 'CRITICAL':
            print(f"[CRITICAL] {message}")


bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/in.h>
#include <linux/tcp.h>

struct exec_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    char args[512];
};

struct network_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u8 proto;
    u8 state;
};

struct file_event_t {
    u32 pid;
    u32 uid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u32 mode;
    u32 flags;
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(network_events);
BPF_PERF_OUTPUT(file_events);


int syscall__execve(struct pt_regs *ctx, const char __user *filename,
                    const char __user *const __user *argv,
                    const char __user *const __user *envp)
{
    struct exec_event_t event = {};
    struct task_struct *task;

    event.pid = bpf_get_current_pid_tgid() >> 32;
    task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.gid = bpf_get_current_uid_gid() >> 32;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    // Capture first few arguments
    char *arg_ptr;
    char arg_buf[64];
    int arg_idx = 0;
    int offset = 0;

    #pragma unroll
    for (int i = 1; i < 8 && offset < sizeof(event.args) - 64; i++) {
        bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), &argv[i]);
        if (arg_ptr) {
            bpf_probe_read_user_str(&arg_buf, sizeof(arg_buf), arg_ptr);
            int len = bpf_probe_read_user_str(&event.args[offset], sizeof(event.args) - offset, arg_ptr);
            if (len > 0) {
                offset += len - 1; // Don't count null terminator
                if (offset < sizeof(event.args) - 1) {
                    event.args[offset++] = ' ';
                }
            }
        } else {
            break;
        }
    }

    exec_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Monitor network connections
int kprobe__tcp_connect(struct pt_regs *ctx, struct sock *sk)
{
    struct network_event_t event = {};
    struct inet_sock *inet = inet_sk(sk);

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    event.saddr = inet->inet_saddr;
    event.daddr = inet->inet_daddr;
    event.sport = inet->inet_sport;
    event.dport = inet->inet_dport;
    event.proto = IPPROTO_TCP;
    event.state = sk->sk_state;

    network_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}

// Monitor file operations
int syscall__openat(struct pt_regs *ctx, int dfd, const char __user *filename, int flags, umode_t mode)
{
    struct file_event_t event = {};

    event.pid = bpf_get_current_pid_tgid() >> 32;
    event.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.mode = mode;
    event.flags = flags;

    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), filename);

    file_events.perf_submit(ctx, &event, sizeof(event));
    return 0;
}
"""

def print_exec_event(cpu, data, size):
    event = b["exec_events"].event(data)
    monitor = EnterpriseEBPFMonitor()

    filename = event.filename.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')
    args = event.args.decode('utf-8', 'replace').strip()

    # Check for suspicious execution patterns
    suspicious = False
    for pattern in monitor.suspicious_patterns['exec']:
        if pattern in filename.encode() or pattern in args.encode():
            suspicious = True
            break

    # Check for privilege escalation attempts
    if event.uid != event.gid and event.uid == 0:
        monitor.log_alert('PRIVILEGE_ESCALATION', 'HIGH',
                         f'Potential privilege escalation: {comm} (PID: {event.pid}, UID: {event.uid})',
                         {'pid': event.pid, 'uid': event.uid, 'command': comm, 'filename': filename})

    # Check for suspicious network tools
    if suspicious:
        monitor.log_alert('SUSPICIOUS_EXEC', 'MEDIUM',
                         f'Suspicious execution: {comm} {args}',
                         {'pid': event.pid, 'ppid': event.ppid, 'command': comm, 'args': args})

    
    with open('/var/log/ghost-sentinel/ebpf_exec.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()} EXEC: PID={event.pid} PPID={event.ppid} UID={event.uid} CMD={comm} FILE={filename} ARGS={args}\n")

def print_network_event(cpu, data, size):
    event = b["network_events"].event(data)
    monitor = EnterpriseEBPFMonitor()

    saddr = socket.inet_ntoa(struct.pack('<I', event.saddr))
    daddr = socket.inet_ntoa(struct.pack('<I', event.daddr))
    sport = socket.ntohs(event.sport)
    dport = socket.ntohs(event.dport)

    comm = event.comm.decode('utf-8', 'replace')


    suspicious_ports = [22, 23, 3389, 4444, 6667, 1337, 31337]
    if dport in suspicious_ports or sport in suspicious_ports:
        monitor.log_alert('SUSPICIOUS_NETWORK', 'MEDIUM',
                         f'Suspicious network connection: {comm} {saddr}:{sport} -> {daddr}:{dport}',
                         {'pid': event.pid, 'src': f'{saddr}:{sport}', 'dst': f'{daddr}:{dport}', 'proto': 'TCP'})

 
    with open('/var/log/ghost-sentinel/ebpf_network.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()} NETWORK: PID={event.pid} CMD={comm} {saddr}:{sport} -> {daddr}:{dport} STATE={event.state}\n")

def print_file_event(cpu, data, size):
    event = b["file_events"].event(data)
    monitor = EnterpriseEBPFMonitor()

    filename = event.filename.decode('utf-8', 'replace')
    comm = event.comm.decode('utf-8', 'replace')

  
    sensitive_files = [
        '/etc/passwd', '/etc/shadow', '/etc/sudoers', '/etc/crontab',
        '/root/.ssh', '/home/.ssh', '/etc/rc.local', '/etc/hosts'
    ]

    for sensitive in sensitive_files:
        if sensitive in filename:
            monitor.log_alert('SENSITIVE_FILE_ACCESS', 'HIGH',
                             f'Sensitive file access: {comm} accessed {filename}',
                             {'pid': event.pid, 'uid': event.uid, 'file': filename, 'command': comm})
            break

  
    with open('/var/log/ghost-sentinel/ebpf_file.log', 'a') as f:
        f.write(f"{datetime.now().isoformat()} FILE: PID={event.pid} UID={event.uid} CMD={comm} FILE={filename} MODE={event.mode} FLAGS={event.flags}\n")

try:
    monitor = EnterpriseEBPFMonitor()

    b = BPF(text=bpf_text)

    # Attach event handlers
    b["exec_events"].open_perf_buffer(print_exec_event)
    b["network_events"].open_perf_buffer(print_network_event)
    b["file_events"].open_perf_buffer(print_file_event)

    print("Enterprise eBPF monitoring started...")

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            print("\nStopping eBPF monitoring...")
            break

except Exception as e:
    print(f"Enterprise eBPF monitoring error: {e}")
    sys.exit(1)
EOF

    
    if cmd python3; then
        python3 "$SCRIPTS_DIR/ghost_sentinel_ebpf_monitor.py" &
        echo $! > "$LOG_DIR/ebpf_monitor.pid"
        log_info "Enterprise eBPF monitoring started (exec, network, file monitoring)"
    fi
}

stop_ebpf_monitoring() {
    if [[ -f "$LOG_DIR/ebpf_monitor.pid" ]]; then
        declare ebpf_pid=$(cat "$LOG_DIR/ebpf_monitor.pid" 2>/dev/null || echo "")
        if [[ -n "$ebpf_pid" ]] && kill -0 "$ebpf_pid" 2>/dev/null; then
            kill "$ebpf_pid" 2>/dev/null || true
        fi
        rm -f "$LOG_DIR/ebpf_monitor.pid"

        # Process enterprise eBPF logs and generate alerts
        if [[ -s "/var/log/ghost-sentinel/ebpf_alerts.jsonl" ]]; then
            declare alert_count=$(wc -l < "/var/log/ghost-sentinel/ebpf_alerts.jsonl" 2>/dev/null || echo 0)
            log_alert "$MEDIUM" "eBPF monitoring detected $alert_count security events"

            # Archive logs
            mv "/var/log/ghost-sentinel/ebpf_alerts.jsonl" "/var/log/ghost-sentinel/ebpf_alerts_$(date +%Y%m%d_%H%M%S).jsonl"
        fi

        # Archive other eBPF logs
        for log_file in "/var/log/ghost-sentinel/ebpf_exec.log" "/var/log/ghost-sentinel/ebpf_network.log" "/var/log/ghost-sentinel/ebpf_file.log"; do
            if [[ -s "$log_file" ]]; then
                mv "$log_file" "${log_file}_$(date +%Y%m%d_%H%M%S).log"
            fi
        done
    fi
    rm -f "$SCRIPTS_DIR/ghost_sentinel_ebpf_monitor.py"
}


start_honeypots() {
    if ! cmd python3; then
        log_info "python3 not available - honeypots disabled"
        return
    fi

    log_info "Starting enterprise honeypot system with dynamic port allocation..."

    # Create enterprise honeypot script
    cat > "$SCRIPTS_DIR/ghost_sentinel_honeypot.py" << 'EOF'

#!/usr/bin/env python3
import sys
import time
import json
import socket
import threading
import random
import ipaddress
from datetime import datetime
from collections import defaultdict
import re

class EnterpriseHoneypot:
    def __init__(self):
        self.active_ports = set()
        self.attack_intelligence = defaultdict(dict)
        self.protocol_handlers = {
            'http': self.handle_http,
            'ssh': self.handle_ssh,
            'ftp': self.handle_ftp,
            'telnet': self.handle_telnet,
            'smtp': self.handle_smtp,
            'generic': self.handle_generic
        }

        # Dynamic port ranges for different protocols
        self.port_ranges = {
            'http': (8000, 8999),
            'https': (9000, 9999),
            'ssh': (2000, 2999),
            'ftp': (3000, 3999),
            'telnet': (4000, 4999),
            'smtp': (5000, 5999),
            'generic': (10000, 19999)
        }

        self.threads = []

    def allocate_dynamic_port(self, protocol):
        """Dynamically allocate an available port for the given protocol"""
        min_port, max_port = self.port_ranges.get(protocol, self.port_ranges['generic'])

        for attempt in range(100):  # Try up to 100 times
            port = random.randint(min_port, max_port)
            if port not in self.active_ports and self.is_port_available(port):
                self.active_ports.add(port)
                return port

      
        min_port, max_port = self.port_ranges['generic']
        for attempt in range(100):
            port = random.randint(min_port, max_port)
            if port not in self.active_ports and self.is_port_available(port):
                self.active_ports.add(port)
                return port

        return None

    def is_port_available(self, port):
        """Check if a port is available for binding"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(('0.0.0.0', port))
                return True
        except OSError:
            return False

    def log_attack(self, protocol, client_ip, client_port, data, attack_type="connection"):
        """Enterprise-grade attack logging with intelligence gathering"""
        attack_data = {
            'timestamp': datetime.now().isoformat(),
            'protocol': protocol,
            'client_ip': client_ip,
            'client_port': client_port,
            'attack_type': attack_type,
            'data_length': len(data) if data else 0,
            'data_sample': data[:500] if data else None,
            'hostname': socket.gethostname(),
            'sensor': 'enterprise_honeypot'
        }

        # Intelligence gathering
        if client_ip not in self.attack_intelligence:
            self.attack_intelligence[client_ip] = {
                'first_seen': attack_data['timestamp'],
                'protocols': set(),
                'attack_types': set(),
                'connection_count': 0,
                'data_volume': 0
            }

        intel = self.attack_intelligence[client_ip]
        intel['protocols'].add(protocol)
        intel['attack_types'].add(attack_type)
        intel['connection_count'] += 1
        intel['data_volume'] += len(data) if data else 0
        intel['last_seen'] = attack_data['timestamp']

       
        with open('/var/log/ghost-sentinel/honeypot_attacks.jsonl', 'a') as f:
            f.write(json.dumps(attack_data) + '\n')

   
        if attack_type in ['exploit_attempt', 'brute_force', 'malware_delivery']:
            print(f"[HONEYPOT ALERT] {attack_type.upper()}: {protocol} from {client_ip}:{client_port}")

    def handle_http(self, client_socket, client_addr):
        """HTTP protocol emulation with attack detection"""
        try:
            data = client_socket.recv(4096).decode('utf-8', errors='ignore')

            # Detect various HTTP-based attacks
            if 'POST' in data and ('<?php' in data or 'eval(' in data):
                self.log_attack('http', client_addr[0], client_addr[1], data, 'webshell_upload')
            elif 'Range: bytes=' in data and '0-18446744073709551615' in data:
                self.log_attack('http', client_addr[0], client_addr[1], data, 'range_header_attack')
            elif re.search(r'User-Agent:\s*(?:sqlmap|nikto|dirbuster|nmap)', data, re.I):
                self.log_attack('http', client_addr[0], client_addr[1], data, 'scanner_detection')
            else:
                self.log_attack('http', client_addr[0], client_addr[1], data, 'http_probe')

            # Send realistic HTTP response
            response = """HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
Content-Type: text/html
Content-Length: 234

<html>
<head><title>Server Status</title></head>
<body>
<h1>Server Online</h1>
<p>This server is running normally.</p>
<p>System load: """ + str(random.uniform(0.1, 2.0))[:4] + """</p>
</body>
</html>"""
            client_socket.send(response.encode())

        except Exception as e:
            self.log_attack('http', client_addr[0], client_addr[1], str(e), 'protocol_error')

    def handle_ssh(self, client_socket, client_addr):
        """SSH protocol emulation"""
        try:
            data = client_socket.recv(1024)

            # SSH banner and version exchange
            if len(data) > 0:
                if data.startswith(b'SSH-'):
                    self.log_attack('ssh', client_addr[0], client_addr[1], data.decode('utf-8', errors='ignore'), 'ssh_probe')
                    # Send fake SSH banner
                    banner = b'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n'
                    client_socket.send(banner)
                else:
                    self.log_attack('ssh', client_addr[0], client_addr[1], data.hex(), 'ssh_malformed')

        except Exception as e:
            self.log_attack('ssh', client_addr[0], client_addr[1], str(e), 'ssh_error')

    def handle_ftp(self, client_socket, client_addr):
        """FTP protocol emulation"""
        try:
            # Send FTP banner
            banner = b'220 FTP Server ready\r\n'
            client_socket.send(banner)

            data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()

            if data.upper().startswith('USER'):
                self.log_attack('ftp', client_addr[0], client_addr[1], data, 'ftp_login_attempt')
                client_socket.send(b'331 Password required\r\n')
            elif data.upper().startswith('PASS'):
                self.log_attack('ftp', client_addr[0], client_addr[1], data, 'ftp_auth_attempt')
                client_socket.send(b'530 Login incorrect\r\n')
            else:
                self.log_attack('ftp', client_addr[0], client_addr[1], data, 'ftp_command')

        except Exception as e:
            self.log_attack('ftp', client_addr[0], client_addr[1], str(e), 'ftp_error')

    def handle_telnet(self, client_socket, client_addr):
        """Telnet protocol emulation"""
        try:
            # Send telnet welcome
            welcome = b'\r\nWelcome to Ubuntu 20.04.3 LTS\r\n\r\nlogin: '
            client_socket.send(welcome)

            data = client_socket.recv(1024).decode('utf-8', errors='ignore')

            if data.strip():
                self.log_attack('telnet', client_addr[0], client_addr[1], data, 'telnet_login_attempt')
                client_socket.send(b'Password: ')

                # Wait for password attempt
                try:
                    client_socket.settimeout(5.0)
                    password = client_socket.recv(1024).decode('utf-8', errors='ignore')
                    if password.strip():
                        self.log_attack('telnet', client_addr[0], client_addr[1], password, 'telnet_auth_attempt')
                except:
                    pass

        except Exception as e:
            self.log_attack('telnet', client_addr[0], client_addr[1], str(e), 'telnet_error')

    def handle_smtp(self, client_socket, client_addr):
        """SMTP protocol emulation"""
        try:
            # Send SMTP greeting
            greeting = b'220 mail.example.com ESMTP Postfix\r\n'
            client_socket.send(greeting)

            data = client_socket.recv(1024).decode('utf-8', errors='ignore').strip()

            if data.upper().startswith('EHLO') or data.upper().startswith('HELO'):
                self.log_attack('smtp', client_addr[0], client_addr[1], data, 'smtp_greeting')
                client_socket.send(b'250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-VRFY\r\n250-ETRN\r\n250-ENHANCEDSTATUSCODES\r\n250-8BITMIME\r\n250-DSN\r\n250-SMTPUTF8\r\n250 CHUNKING\r\n')
            elif data.upper().startswith('MAIL FROM'):
                self.log_attack('smtp', client_addr[0], client_addr[1], data, 'smtp_spam_attempt')
            else:
                self.log_attack('smtp', client_addr[0], client_addr[1], data, 'smtp_probe')

        except Exception as e:
            self.log_attack('smtp', client_addr[0], client_addr[1], str(e), 'smtp_error')

    def handle_generic(self, client_socket, client_addr):
        """Generic protocol handler for unknown services"""
        try:
            data = client_socket.recv(1024)

            if len(data) > 0:
                # Try to identify protocol
                if data.startswith(b'GET ') or data.startswith(b'POST ') or data.startswith(b'HEAD '):
                    return self.handle_http(client_socket, client_addr)
                elif data.startswith(b'SSH-'):
                    return self.handle_ssh(client_socket, client_addr)
                elif data.startswith(b'USER ') or data.startswith(b'PASS '):
                    return self.handle_ftp(client_socket, client_addr)
                else:
                    self.log_attack('generic', client_addr[0], client_addr[1], data.hex(), 'unknown_protocol')

        except Exception as e:
            self.log_attack('generic', client_addr[0], client_addr[1], str(e), 'generic_error')

    def start_honeypot_listener(self, protocol, port):
        """Start a honeypot listener for a specific protocol and port"""
        def listener_thread():
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server_socket.bind(('0.0.0.0', port))
                server_socket.listen(5)
                server_socket.settimeout(1.0)  # Allow clean shutdown

                print(f"Honeypot listening on {protocol} port {port}")

                while not shutdown_event.is_set():
                    try:
                        client_socket, client_addr = server_socket.accept()
                        client_socket.settimeout(10.0)

                        # Handle connection in a separate thread
                        handler_thread = threading.Thread(
                            target=self.protocol_handlers.get(protocol, self.handle_generic),
                            args=(client_socket, client_addr)
                        )
                        handler_thread.daemon = True
                        handler_thread.start()

                    except socket.timeout:
                        continue
                    except OSError:
                        break

                server_socket.close()
                print(f"Honeypot stopped on {protocol} port {port}")

            except Exception as e:
                print(f"Honeypot error on {protocol} port {port}: {e}")

        thread = threading.Thread(target=listener_thread)
        thread.daemon = True
        thread.start()
        self.threads.append(thread)

    def generate_intelligence_report(self):
        """Generate intelligence report on attackers"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_attackers': len(self.attack_intelligence),
            'top_attackers': [],
            'protocol_distribution': defaultdict(int),
            'attack_type_distribution': defaultdict(int)
        }

        # Sort attackers by connection count
        sorted_attackers = sorted(
            self.attack_intelligence.items(),
            key=lambda x: x[1]['connection_count'],
            reverse=True
        )[:10]  # Top 10

        for ip, intel in sorted_attackers:
            report['top_attackers'].append({
                'ip': ip,
                'connections': intel['connection_count'],
                'protocols': list(intel['protocols']),
                'attack_types': list(intel['attack_types']),
                'first_seen': intel['first_seen'],
                'last_seen': intel['last_seen']
            })

            for protocol in intel['protocols']:
                report['protocol_distribution'][protocol] += 1

            for attack_type in intel['attack_types']:
                report['attack_type_distribution'][attack_type] += 1

        with open('/var/log/ghost-sentinel/honeypot_intelligence.json', 'w') as f:
            json.dump(report, f, indent=2)

        return report


shutdown_event = threading.Event()

def main():
    honeypot = EnterpriseHoneypot()

   
    protocols_to_start = ['http', 'ssh', 'ftp', 'telnet', 'smtp']

    for protocol in protocols_to_start:
        port = honeypot.allocate_dynamic_port(protocol)
        if port:
            honeypot.start_honeypot_listener(protocol, port)
            print(f"Started {protocol} honeypot on port {port}")
        else:
            print(f"Failed to allocate port for {protocol}")


    for i in range(3):
        port = honeypot.allocate_dynamic_port('generic')
        if port:
            honeypot.start_honeypot_listener('generic', port)
            print(f"Started generic honeypot on port {port}")

    print("Enterprise honeypot system active. Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(60)  # Generate intelligence report every minute
            report = honeypot.generate_intelligence_report()
            if report['total_attackers'] > 0:
                print(f"Intelligence: {report['total_attackers']} unique attackers detected")

    except KeyboardInterrupt:
        print("\nShutting down honeypot system...")
        shutdown_event.set()

        # Generate final intelligence report
        final_report = honeypot.generate_intelligence_report()
        print(f"Final report: {final_report['total_attackers']} attackers, {sum(final_report['protocol_distribution'].values())} total connections")

if __name__ == '__main__':
    main()
EOF


    if cmd python3; then
        python3 "$SCRIPTS_DIR/ghost_sentinel_honeypot.py" &
        echo $! > "$LOG_DIR/honeypot.pid"
        log_info "Enterprise honeypot system started with dynamic port allocation"
    fi
}

stop_honeypots() {
    log_info "Stopping enterprise honeypot system..."

   
    if [[ -f "$LOG_DIR/honeypot.pid" ]]; then
        kill -TERM $(cat "$LOG_DIR/honeypot.pid") 2>/dev/null
        rm -f "$LOG_DIR/honeypot.pid"
    fi


    if [[ -f "$LOG_DIR/honeypot.pids" ]]; then
        while read -r pid; do
            kill -TERM "$pid" 2>/dev/null
        done < "$LOG_DIR/honeypot.pids"
        rm -f "$LOG_DIR/honeypot.pids"
    fi

 
    if [[ -f "$SCRIPTS_DIR/ghost_sentinel_honeypot.py" ]]; then
        log_info "Generating final honeypot intelligence report..."
        python3 -c "
import json
from collections import defaultdict
from datetime import datetime


attacks = []
try:
    with open('/var/log/ghost-sentinel/honeypot_attacks.jsonl', 'r') as f:
        for line in f:
            attacks.append(json.loads(line))
except FileNotFoundError:
    pass

if attacks:
    summary = {
        'total_attacks': len(attacks),
        'unique_attackers': len(set(a['client_ip'] for a in attacks)),
        'protocols': list(set(a['protocol'] for a in attacks)),
        'attack_types': list(set(a['attack_type'] for a in attacks)),
        'time_range': {
            'start': min(a['timestamp'] for a in attacks),
            'end': max(a['timestamp'] for a in attacks)
        }
    }
    
    with open('/var/log/ghost-sentinel/honeypot_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f'Honeypot session summary: {summary[\"total_attacks\"]} attacks from {summary[\"unique_attackers\"]} unique IPs')
else:
    print('No honeypot activity detected')
"

    fi

    log_info "Enterprise honeypot system stopped"
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
        declare suspicious_symbols=$(grep -E "(hijack|detour)" /proc/kallsyms 2>/dev/null | grep -vE '(setup_detour_execution$|arch_uretprobe_hijack_return_addr)' || echo "")
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
    # Compare outputs to detect hiding
    local ss_ports="$(ss -Htulnp 2>/dev/null | grep -oE ":[0-9]+ " | sort -u | wc -l)"
    local netstat_ports="$(netstat -tulnp 2>/dev/null | tail -n +3 | grep -oE ":[0-9]+ " | sort -u | wc -l)"
    # XXX lsof produces output which is not comparable with ss or netstat
    local lsof_ports="$(lsof -i -P -n 2>/dev/null | grep -vF -- '->' | grep -oE ":[0-9]+ " | sort -u | wc -l)"
    if [ "$lsof_ports" -eq 0 ]; then
    echo "[!] Warning: 'lsof' returned 0 ports. This may be due to insufficient privileges (try running as root)."
    fi
    local diff_ss_netstat="$(( ss_ports - netstat_ports ))"
    local diff_ss_lsof="$(( lsof_ports - ss_ports ))"
    local max_diff=5
    if [[ ${diff_ss_netstat#-} -gt $max_diff || ${diff_ss_lsof#-} -gt $max_diff ]]; then
        log_alert $HIGH "Network tool output inconsistency detected (ss: $ss_ports, netstat: $netstat_ports, lsof: $lsof_ports)"
    fi

    # Check for suspicious RAW sockets
    if [[ -r /proc/net/raw ]]; then
        local raw_sockets="$(grep -v "sl" /proc/net/raw 2>/dev/null | wc -l)"
        if [[ $raw_sockets -gt 3 ]]; then
            log_alert $MEDIUM "Multiple RAW sockets detected: $raw_sockets"
        fi
    fi

    # Monitor for covert channels
    local icmp_traffic="$(grep "ICMP" /proc/net/snmp 2>/dev/null | tail -1 | awk '{print $3}' || echo 0)"
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
            find "$location" -maxdepth 2 -type f -mtime -1 2>/dev/null | while read -r file; do
                # Skip very large files for performance
                declare file_size=$(stat -c%s "$file" 2>/dev/null || echo 0)
                if [[ $file_size -gt 1048576 ]]; then  # Skip files > 1MB
                    continue
                fi

                # Perform YARA scan if available
                if [[ "$HAS_YARA" == true ]]; then
                    declare yara_result=""
                    yara_result+=$(find "$YARA_RULES_DIR" -name '*.yar' -print0 | xargs -0 -I {} yara -s {} -r "$file" 2>/dev/null || echo "")
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
            done || true
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
        chmod 700 "$forensic_dir"

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
        if cmd strings; then
            strings "$file" | head -100 > "$forensic_dir/${quarantine_name}.strings" 2>/dev/null || true
        fi

        if [[ "${QUARANTINE_ENABLE-true}" == "false" ]]; then
          return
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
    for dir in "$LOG_DIR" "$BASELINE_DIR" "$ALERTS_DIR" "$QUARANTINE_DIR" "$BACKUP_DIR" "$THREAT_INTEL_DIR" "$YARA_RULES_DIR" "$SCRIPTS_DIR"; do
        if ! mkdir -p "$dir" 2>/dev/null; then
           
            echo -e "${RED}[ERROR]${NC} Cannot create directory: $dir"
            echo "Please run as root or ensure write permissions"
            exit 1
        fi
    done

    # Set secure permissions (700 - owner only) on ALL security-sensitive directories
    chmod 700 "$LOG_DIR" "$BASELINE_DIR" "$ALERTS_DIR" "$QUARANTINE_DIR" "$BACKUP_DIR" "$THREAT_INTEL_DIR" "$YARA_RULES_DIR" "$SCRIPTS_DIR"

            declare today=$(date +%Y%m%d)
            declare alert_file="$ALERTS_DIR/$today.log"
            echo "=== Ghost Sentinel v4 - $(date '+%Y-%m-%d %H:%M:%S') ===" > "$alert_file"

    # Load configuration BEFORE doing anything else
    load_config_safe

    # Check dependencies
    check_dependencies

    # Initialize components
    init_json_output
    init_yara_rules

    log_info "Initializing Ghost Sentinel v4..."

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
    "yara_scanning": false
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
    WHITELIST_PROCESSES=${WHITELIST_PROCESSES:-("firefox" "chrome" "nmap" "masscan" "nuclei" "gobuster" "ffuf" "subfinder" "httpx" "amass" "burpsuite" "wireshark" "metasploit" "sqlmap" "nikto" "dirb" "wpscan" "john" "docker" "containerd" "systemd" "kthreadd" "bash" "zsh" "ssh" "python3" "yara")}
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
    if [[ "${SYSLOG_ENABLED:-false}" == true ]] && cmd logger; then
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
        if cmd mail; then
            echo "CRITICAL SECURITY ALERT: $message" | mail -s "Ghost Sentinel Alert" "$EMAIL_RECIPIENT" 2>/dev/null || true
        elif cmd sendmail; then
            echo -e "Subject: Ghost Sentinel Critical Alert\n\nCRITICAL SECURITY ALERT: $message" | sendmail "$EMAIL_RECIPIENT" 2>/dev/null || true
        fi
    fi

    # Webhook notification with improved error handling
    if [[ -n "$WEBHOOK_URL" ]] && cmd curl; then
        curl -s --max-time 10 -X POST "$WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"alert\":\"CRITICAL\",\"message\":\"$message\",\"timestamp\":\"$(date -Iseconds)\",\"hostname\":\"$(hostname)\"}" 2>/dev/null || true
    fi

    # Slack webhook with rich formatting
    if [[ -n "$SLACK_WEBHOOK_URL" ]] && cmd curl; then
        declare payload=$(cat << EOF
{
    "attachments": [
        {
            "color": "danger",
            "title": "🚨 Ghost Sentinel v4 Critical Alert",
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
            "footer": "Ghost Sentinel v4",
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
        if cmd notify-send; then
            notify-send "Ghost Sentinel" "CRITICAL: $message" --urgency=critical 2>/dev/null || true
        elif cmd zenity; then
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
        if cmd curl; then
            if curl -s --max-time 30 -o "$temp_file" "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset" 2>/dev/null; then
                # Better validation - check for IP addresses and reasonable file size
                if [[ -s "$temp_file" ]] && [[ $(grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+" "$temp_file" | wc -l) -gt 100 ]]; then
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
    if [[ -n "$ABUSEIPDB_API_KEY" ]] && cmd curl; then
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
            if cmd jq; then
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
    if cmd ss; then
        ss -tulnp --no-header > "$BASELINE_DIR/network_baseline.txt" 2>/dev/null || true
    elif cmd netstat; then
        netstat -tulnp --numeric-hosts --numeric-ports > "$BASELINE_DIR/network_baseline.txt" 2>/dev/null || true
    fi

    # Process baseline (structured)
    ps -eo pid,ppid,user,comm,cmd --no-headers > "$BASELINE_DIR/process_baseline.txt" 2>/dev/null || true

    # Services baseline
    if cmd systemctl; then
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
    if cmd last; then
        last -n 10 --time-format=iso > "$BASELINE_DIR/last_baseline.txt" 2>/dev/null || true
    fi

    # Package state (hash only for performance)
    declare pkg_hash=""
    if [[ "$IS_DEBIAN" == true ]]; then
        pkg_hash=$(dpkg -l 2>/dev/null | sha256sum | cut -d' ' -f1)
        dpkg --get-selections | sort -u > "$BASELINE_DIR/packages_list.txt"
    elif [[ "$IS_FEDORA" == true ]]; then
        pkg_hash=$(rpm -qa --queryformat="%{NAME}-%{VERSION}-%{RELEASE}\n" 2>/dev/null | sort | sha256sum | cut -d' ' -f1)
    elif cmd pacman; then
        pacman -Qq | sort -u > "$BASELINE_DIR/packages_list.txt"
        pkg_hash=$(pacman -Q | sort | sha256sum | cut -d' ' -f1)
    fi

    if [[ "$IS_NIXOS" == true ]]; then
        pkg_hash=$(nix-store --query --requisites /run/current-system | cut -d- -f2- | sort | uniq)
    fi

    if [[ -n "$pkg_hash" ]]; then
        echo "$pkg_hash" > "$BASELINE_DIR/packages_hash.txt"
    fi

    # SUID/SGID baseline (limited scope)
    find /usr/bin /usr/sbin /bin /sbin -maxdepth 1 -perm /4000 -o -perm /2000 2>/dev/null | sort > "$BASELINE_DIR/suid_baseline.txt" || true

    log_info "Baseline created successfully"
}

# Production main function with all v4 features
main_enhanced() {
    declare start_time=$(date +%s)

    log_info "Ghost Sentinel v4 Enhanced - Starting advanced security scan..."

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

    if [[ "$ENABLE_HONEYPOTS" == true ]]; then
        start_honeypots
        features_enabled+=("honeypots")
        json_set "$JSON_OUTPUT_FILE" ".features.honeypots" "true"
    fi

    if [[ "$ENABLE_YARA" == true ]] && [[ "$HAS_YARA" == true ]]; then
        features_enabled+=("yara")
        json_set "$JSON_OUTPUT_FILE" ".features.yara_scanning" "true"
    fi

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

    if [[ "$HAS_YARA" == true ]]; then
        log_info "Running file monitoring with YARA..."
        if monitor_files_with_yara; then
            modules_run+=("files-yara")
        fi
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

    # Update final JSON metadata
    json_set "$JSON_OUTPUT_FILE" ".scan_end" "$(date -Iseconds)"
    json_set "$JSON_OUTPUT_FILE" ".performance.scan_duration" "$duration"

    # Generate comprehensive summary
    generate_enhanced_summary "$duration" "${modules_run[@]}"

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

    declare alert_count=0
    declare critical_count=0
    declare high_count=0
    declare medium_count=0
    declare low_count=0

    if [[ -f "$alert_file" ]]; then
        alert_count=$(grep -c "^\[" "$alert_file" 2>/dev/null || echo 0)
        critical_count=$(grep -c "CRITICAL" "$alert_file" 2>/dev/null || echo 0)
        high_count=$(grep -c "HIGH" "$alert_file" 2>/dev/null || echo 0)
        medium_count=$(grep -c "MEDIUM" "$alert_file" 2>/dev/null || echo 0)
        low_count=$(grep -c "LOW" "$alert_file" 2>/dev/null || echo 0)
    fi

# Ensure counts are numeric (fix for arithmetic errors)
alert_count=${alert_count:-0}
alert_count=${alert_count//[^0-9]/}
alert_count=$(( alert_count + 0 )) 2>/dev/null || alert_count=0
critical_count=${critical_count:-0}
critical_count=${critical_count//[^0-9]/}
critical_count=$(( critical_count + 0 )) 2>/dev/null || critical_count=0
high_count=${high_count:-0}
high_count=${high_count//[^0-9]/}
high_count=$(( high_count + 0 )) 2>/dev/null || high_count=0
medium_count=${medium_count:-0}
medium_count=${medium_count//[^0-9]/}
medium_count=$(( medium_count + 0 )) 2>/dev/null || medium_count=0
low_count=${low_count:-0}
low_count=${low_count//[^0-9]/}
low_count=$(( low_count + 0 )) 2>/dev/null || low_count=0    echo
    echo -e "${CYAN}=== GHOST SENTINEL v4 ADVANCED SECURITY SUMMARY ===${NC}"
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

    if [[ ${#active_features[@]} -gt 0 ]]; then
        echo -e "${PURPLE}Active Features: ${active_features[*]}${NC}"
    fi

if (( critical_count > 0 )) || (( high_count > 0 )); then
    echo -e "\n${RED}Priority Alerts:${NC}"
    while read line; do
        level=$(echo "$line" | grep -o "\[LEVEL:[0-9]\]" | grep -o "[0-9]")
        msg=$(echo "$line" | cut -d']' -f3- | sed 's/^ *//')
        if [[ "$level" == "1" ]]; then
            echo -e "${RED}   CRITICAL: $msg${NC}"
        else
            echo -e "${YELLOW}   HIGH: $msg${NC}"
        fi
    done < <(grep -E "(CRITICAL|HIGH)" "$alert_file" 2>/dev/null | tail -5)
else
    echo -e "${GREEN}✓ No critical threats detected${NC}"
fi

    # Integrity status
    declare baseline_age=0
    if [[ -f "$BASELINE_DIR/.initialized" ]]; then
        baseline_age=$(( ($(date +%s) - $(stat -c %Y "$BASELINE_DIR/.initialized" 2>/dev/null || echo $(date +%s))) / 86400 ))
    fi
    echo -e "${CYAN}Baseline Age: $baseline_age days${NC}"

    if (( baseline_age > 30 )); then
        echo -e "${YELLOW}  Consider updating baseline (run with 'baseline' option)${NC}"
    fi
}

# Minimal required functions for compatibility
monitor_network() { monitor_network_advanced; }

monitor_processes() {
    if [[ "$MONITOR_PROCESSES" != true ]]; then return; fi
    log_info "Basic process monitoring..."

    # Check for suspicious processes
    declare suspicious_procs=("^nc" "netcat" "socat" "ncat")
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

monitor_files() {
    if [[ "$HAS_YARA" == true ]]; then
        monitor_files_with_yara
    fi
}

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
        declare mem_usage=$(echo "$line" | awk '{print $4}' | tr -d '\n\r')
        declare proc_name=$(echo "$line" | awk '{print $11}' | xargs basename 2>/dev/null)
        declare pid=$(echo "$line" | awk '{print $2}')

        if ! is_whitelisted_process "$proc_name"; then
            if [[ -n "$mem_usage" ]] && [[ "$mem_usage" =~ ^[0-9]+\.?[0-9]*$ ]] && (( $(echo "$mem_usage > 80" | bc -l 2>/dev/null || echo 0) )); then
                log_alert $MEDIUM "High memory usage: $proc_name (PID: $pid, MEM: $mem_usage%)"
            fi
        fi
    done
}

# Original compatibility function
main() {
    log_info "Ghost Sentinel v4 starting security scan..."

    init_sentinel

    monitor_network
    monitor_processes
    monitor_files
    monitor_users
    monitor_rootkits
    monitor_memory

    log_info "Security scan completed"

    declare today=$(date +%Y%m%d)
    declare alert_count=$(grep -c "^\[" "$ALERTS_DIR/$today.log" 2>/dev/null)
    alert_count=${alert_count:-0}

    if (( alert_count > 0 )); then
        echo -e "${YELLOW}Security Summary: $alert_count alerts generated${NC}"
        echo -e "${YELLOW}Check: $ALERTS_DIR/$today.log${NC}"
    else
        echo -e "${GREEN}Security Summary: No threats detected${NC}"
    fi
}

# Enhanced installation with systemd integration
install_cron() {
    declare cron_entry="0 * * * * $SCRIPT_DIR/$SCRIPT_NAME >/dev/null 2>&1"

    if cmd crontab; then
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
    if cmd systemctl; then
        create_systemd_service
    fi
}

# Create systemd service for enhanced integration
create_systemd_service() {
    declare systemd_args=""
    if [[ "$EUID" -eq 0 ]]; then
        declare service_file="/etc/systemd/system/ghost-sentinel.service"
        declare timer_file="/etc/systemd/system/ghost-sentinel.timer"
    else
        declare service_file="$HOME/.config/systemd/user/ghost-sentinel.service"
        declare timer_file="$HOME/.config/systemd/user/ghost-sentinel.timer"
        systemd_args="--user"
    fi
    cat > "$service_file" << EOF
[Unit]
Description=Ghost Sentinel v4 Security Monitor
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

    systemctl ${systemd_args} daemon-reload
    systemctl enable ${systemd_args} ghost-sentinel.timer
    systemctl start ${systemd_args} ghost-sentinel.timer

    log_info "Systemd service and timer installed"
}

# Secure self-update with integrity verification
self_update() {
    log_info "Checking for updates with integrity verification..."

    declare update_url="https://raw.githubusercontent.com/your-repo/ghost-sentinel/main/ghost_sentinel.sh"
    declare temp_file=$(mktemp)
    declare temp_sig=$(mktemp)

    if cmd curl; then
        # Download script and signature
        if curl -s --max-time 30 -o "$temp_file" "$update_url" && \
           curl -s --max-time 30 -o "$temp_sig" "$update_url.sig"; then

            # Verify GPG signature if available
            if cmd gpg && [[ -s "$temp_sig" ]]; then
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

# Command line interface with new v4 options
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
    echo "Testing Ghost Sentinel v4..."
    init_sentinel
    log_alert $HIGH "Test alert - Ghost Sentinel v4 is working"
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
    create_systemd_service
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
    echo "You can now run: sudo ./theprotector.sh test"
    ;;
"status")
    echo "Ghost Sentinel v4 Status:"
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
    init_sentinel
    if [[ "$HAS_YARA" == true ]]; then
        monitor_files_with_yara
    else
        echo "YARA not available - install yara package"
    fi
    ;;
"ebpf")
    init_sentinel
    if [[ "$HAS_BCC" == true ]] && [[ $EUID -eq 0 ]]; then
        start_ebpf_monitoring
        echo "eBPF monitoring started. Press Ctrl+C to stop."
        read -r
        stop_ebpf_monitoring
    else
        echo "eBPF monitoring requires root privileges and BCC tools"
    fi
    ;;
"uninstall")
    echo "Ghost Sentinel v4 - Complete Uninstall"
    echo "=============================================="
    echo ""
    echo " WARNING: This will permanently remove ALL Ghost Sentinel files,"
    echo "   logs, configurations, and data. This action cannot be undone!"
    echo ""
    echo "The following will be removed:"
    echo "  • All log files and security alerts"
    echo "  • YARA rules and malware signatures"
    echo "  • Threat intelligence databases"
    echo "  • Quarantined files and forensics"
    echo "  • Configuration files and scripts"
    echo "  • Systemd services (if installed)"
    echo "  • Scheduled tasks and cron jobs"
    echo ""

    # Ask for confirmation
    read -p "Do you want to keep logs for analysis? (y/N): " -n 1 -r
    echo
    declare keep_logs=false
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        keep_logs=true
        echo "✓ Logs will be preserved in ~/ghost-sentinel-backup/"
    fi

    echo ""
    read -p "Are you sure you want to uninstall Ghost Sentinel? (type 'YES' to confirm): " confirm
    if [[ "$confirm" != "YES" ]]; then
        echo "Uninstall cancelled."
        exit 0
    fi

    echo ""
    echo " Stopping all Ghost Sentinel processes..."

    # Stop all running components
    stop_honeypots
    stop_ebpf_monitoring

    # Kill any remaining processes
    pkill -f "ghost_sentinel" 2>/dev/null || true
    pkill -f "ghost-sentinel" 2>/dev/null || true
    pkill -f "python3.*ghost_sentinel" 2>/dev/null || true

    # Clean up temp files
    rm -f /tmp/ghost_sentinel_* /tmp/ghost-sentinel*

    # Remove lock files
    rm -f "$LOCK_FILE" "$PID_FILE"

    echo " Backing up and removing files..."

    # Create backup directory if keeping logs
    if [[ "$keep_logs" == true ]]; then
        declare backup_dir="$HOME/ghost-sentinel-backup"
        mkdir -p "$backup_dir"

        # Copy logs and alerts
        if [[ -d "$LOG_DIR" ]]; then
            cp -r "$LOG_DIR" "$backup_dir/" 2>/dev/null || true
        fi
        if [[ -d "$ALERTS_DIR" ]]; then
            cp -r "$ALERTS_DIR" "$backup_dir/" 2>/dev/null || true
        fi

        echo "✓ Logs backed up to: $backup_dir"
    fi

    # Remove all Ghost Sentinel directories
    declare dirs_to_remove=(
        "$LOG_DIR"
        "$BASELINE_DIR"
        "$ALERTS_DIR"
        "$QUARANTINE_DIR"
        "$BACKUP_DIR"
        "$THREAT_INTEL_DIR"
        "$YARA_RULES_DIR"
        "$SCRIPTS_DIR"
    )

    for dir in "${dirs_to_remove[@]}"; do
        if [[ -d "$dir" ]]; then
            rm -rf "$dir" 2>/dev/null || true
            echo "✓ Removed directory: $dir"
        fi
    done

    # Remove configuration file
    if [[ -f "$CONFIG_FILE" ]]; then
        rm -f "$CONFIG_FILE" 2>/dev/null || true
        echo "✓ Removed configuration: $CONFIG_FILE"
    fi

    # Remove systemd service if it exists
    if [[ $EUID -eq 0 ]] && cmd systemctl; then
        if systemctl is-active --quiet ghost-sentinel 2>/dev/null; then
            systemctl stop ghost-sentinel 2>/dev/null || true
            systemctl disable ghost-sentinel 2>/dev/null || true
        fi

        declare service_file="/etc/systemd/system/ghost-sentinel.service"
        if [[ -f "$service_file" ]]; then
            rm -f "$service_file" 2>/dev/null || true
            systemctl daemon-reload 2>/dev/null || true
            echo "✓ Removed systemd service: $service_file"
        fi
    fi

    # Remove cron jobs
    if cmd crontab && [[ $EUID -ne 0 ]]; then
        # Remove user cron jobs
        crontab -l 2>/dev/null | grep -v "ghost-sentinel\|theprotector" | crontab - 2>/dev/null || true
    fi

    # Remove system cron jobs (if root)
    if [[ $EUID -eq 0 ]]; then
        declare cron_files=(
            "/etc/cron.d/ghost-sentinel"
            "/etc/cron.daily/ghost-sentinel"
            "/etc/cron.hourly/ghost-sentinel"
            "/etc/cron.weekly/ghost-sentinel"
            "/etc/cron.monthly/ghost-sentinel"
        )

        for cron_file in "${cron_files[@]}"; do
            if [[ -f "$cron_file" ]]; then
                rm -f "$cron_file" 2>/dev/null || true
                echo "✓ Removed cron job: $cron_file"
            fi
        done
    fi

    # Remove logrotate configuration
    declare logrotate_file="/etc/logrotate.d/ghost-sentinel"
    if [[ -f "$logrotate_file" ]]; then
        rm -f "$logrotate_file" 2>/dev/null || true
        echo "✓ Removed logrotate config: $logrotate_file"
    fi

    # Remove any remaining script copies
    find /usr/local/bin -name "*ghost-sentinel*" -type f -delete 2>/dev/null || true
    find /usr/local/bin -name "*theprotector*" -type f -delete 2>/dev/null || true

    # Clean up any remaining temporary files
    find /tmp -name "*ghost*" -type f -delete 2>/dev/null || true
    find /var/tmp -name "*ghost*" -type f -delete 2>/dev/null || true

    echo ""
    echo "Ghost Sentinel v4 has been completely uninstalled!"
    echo ""
    if [[ "$keep_logs" == true ]]; then
        echo "Logs preserved in: $backup_dir"
        echo "   You can safely delete this directory when no longer needed."
        echo ""
    fi
    echo "System cleanup complete. All traces of Ghost Sentinel removed."
    echo ""
    echo "If you want to reinstall later, download the script again."
    ;;
"dashboard")
    echo "Starting Ghost Sentinel Dashboard..."
    echo "===================================="
    
    # Check if theProtector.go exists
    if [[ ! -f "theProtector.go" ]]; then
        echo -e "${RED}✗ Dashboard file 'theProtector.go' not found in current directory${NC}"
        echo "Please ensure theProtector.go is in the same directory as theProtectorV4.sh"
        exit 1
    fi
    
    # Check if Go is installed
    if ! command -v go &> /dev/null; then
        echo -e "${RED}✗ Go is not installed. Please install Go to run the dashboard.${NC}"
        exit 1
    fi
    
    echo -e "${GREEN}✓ Starting dashboard on http://localhost:8082${NC}"
    echo "Press Ctrl+C to stop the dashboard"
    echo ""
    
    # Run the dashboard
    go run theProtector.go
    ;;
*)
    main
    ;;
esac
