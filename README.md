# TheProtectorV4 - Advanced Linux Security Monitor

TheProtectorV4 is a comprehensive, security monitoring system for Linux that provides real-time threat detection, malware scanning, and forensic analysis. It combines multiple security technologies including YARA malware detection, eBPF kernel monitoring, honeypots, and advanced threat intelligence.

## Features

### Core Security Monitoring
- **YARA Malware Detection**: Advanced pattern-based malware scanning with enterprise rules
- **eBPF Kernel Monitoring**: Real-time process, network, and file system monitoring  
- **Honeypot System**: Dynamic port allocation honeypots to detect and analyze attacks
- **Threat Intelligence**: Integration with threat intelligence feeds
- **Forensic Analysis**: Comprehensive logging and evidence collection

### Advanced Capabilities
- **Anti-Evasion Detection**: Identifies rootkit hiding techniques and process manipulation
- **Network Monitoring**: Advanced network traffic analysis with private IP filtering
- **Process Monitoring**: Real-time process behavior analysis
- **File Integrity Monitoring**: Critical system file change detection
- **User Activity Monitoring**: Login and user account anomaly detection

### Dashboard
- **Web Interface**: Go-based dashboard for real-time monitoring and alerts
- **RESTful API**: Programmatic access to security data
- **Interactive Charts**: Visual representation of security metrics

## Supported Linux Distributions

TheProtectorV4 supports the following Linux distributions:
- **Debian/Ubuntu** (primary support)
- **Fedora/RHEL/CentOS** 
- **Arch Linux** (with pacman)
- **NixOS**
- **General Linux** (with manual dependency installation)

## System Requirements

- **Architecture**: x86_64, ARM64
- **Kernel**: Linux 4.15+ (for eBPF support)
- **Memory**: 512MB minimum, 2GB recommended
- **Storage**: 100MB for logs and quarantine
- **Permissions**: Root access required for full functionality

## Dependencies

### Core Dependencies

#### Package Manager Installation

**Debian/Ubuntu:**
```bash
sudo apt update
sudo apt install -y jq inotify-tools yara curl netcat-traditional python3 python3-pip
```

**Fedora/RHEL/CentOS:**
```bash
sudo dnf install -y jq inotify-tools yara curl nc python3 python3-pip
# or for older systems:
sudo yum install -y jq inotify-tools yara curl nc python3 python3-pip
```

**Arch Linux:**
```bash
sudo pacman -S jq inotify-tools yara curl netcat python python-pip
```

#### BCC/eBPF Tools

**Ubuntu/Debian:**
```bash
sudo apt install -y bpfcc-tools linux-headers-$(uname -r)
```

**Fedora:**
```bash
sudo dnf install -y bcc bcc-tools kernel-headers
```

**Arch Linux:**
```bash
sudo pacman -S bcc bcc-tools linux-headers
```

#### Manual Installation (if packages unavailable)

**YARA:**
```bash
wget https://github.com/VirusTotal/yara/archive/v4.2.3.tar.gz
tar -xzf v4.2.3.tar.gz
cd yara-4.2.3
./bootstrap.sh
./configure
make
sudo make install
```

**BCC:**
```bash
git clone https://github.com/iovisor/bcc.git
cd bcc
git submodule update --init --recursive
mkdir build && cd build
cmake ..
make
sudo make install
```

### Go Dashboard Dependencies

**Go Installation:**

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y golang-go
```

**Fedora:**
```bash
sudo dnf install -y golang
```

**Arch Linux:**
```bash
sudo pacman -S go
```

**Manual Installation:**
```bash
wget https://golang.org/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

### Python Dependencies

The eBPF monitor requires Python 3 with the following modules:
- `bcc` (installed with BCC)
- `ipaddress` (built-in)
- `json` (built-in) 
- `threading` (built-in)
- `socket` (built-in)
- `struct` (built-in)

## Installation

1. **Clone or download the scripts:**
   ```bash
   # Ensure you have theProtectorV4.sh and theProtector.go in the same directory
   ls -la
   # Should show: theProtectorV4.sh theProtector.go
   ```

2. **Make the script executable:**
   ```bash
   chmod +x theProtectorV4.sh
   ```

3. **Run initial setup:**
   ```bash
   sudo ./theProtectorV4.sh test
   ```

## Usage

### Basic Security Scan

```bash
sudo ./theProtectorV4.sh
```

### Enhanced Security Scan (Recommended)

```bash
sudo ./theProtectorV4.sh enhanced
```

This enables all features including eBPF monitoring and honeypots.

### Continuous Monitoring

```bash
sudo ./theProtectorV4.sh loop
```

Runs continuous monitoring with randomized scan intervals (1-5 minutes). Background services (honeypots, eBPF monitoring) are started once at initialization and only refreshed if they become inactive, preventing resource accumulation.

> **Note**: In loop mode, the script uses a locking mechanism to prevent multiple simultaneous scans. If you see "Waiting for previous scan to complete (PID: XXXX)", it means a previous instance of the script is still running its security scan. The current instance will wait for the previous scan to finish before starting a new one, ensuring comprehensive analysis without conflicts.

### Dashboard

```bash
sudo ./theProtectorV4.sh dashboard
```

Starts the Go-based web dashboard on http://localhost:8082

### Available Commands

- `run` - Basic security scan
- `enhanced` - Full security scan with all features
- `test` - Test installation and capabilities
- `baseline` - Create security baseline
- `logs` - View security logs
- `alerts` - View current alerts
- `json` - Export data in JSON format
- `status` - Show monitoring status
- `dashboard` - Start web dashboard
- `loop` - Continuous monitoring mode
- `cleanup` - Clean up processes and fix issues
- `reset-integrity` - Reset script integrity hash

### Configuration

The script uses environment variables for configuration. You can create a `sentinel.conf` file in the same directory:

```bash
# Example sentinel.conf
MONITOR_NETWORK=true
MONITOR_PROCESSES=true
ENABLE_EBPF=true
ENABLE_HONEYPOTS=true
WEBHOOK_URL="https://your-webhook-url"
SLACK_WEBHOOK_URL="https://hooks.slack.com/your-slack-webhook"
EMAIL_RECIPIENT="admin@yourdomain.com"
```

## Directory Structure

```
/var/lib/ghost-sentinel/ (root) or ~/.ghost-sentinel/ (user)
├── logs/
│   ├── sentinel.log
│   ├── alerts/
│   ├── baseline/
│   ├── quarantine/
│   ├── ebpf_forensics.jsonl
│   ├── honeypot_attacks.jsonl
│   └── whitelisted_files.txt
├── scripts/
│   ├── ghost_sentinel_ebpf_monitor.py
│   └── ghost_sentinel_honeypot.py
└── backups/
```

## Security Features Explained

### YARA Malware Detection
Scans files for malware patterns using comprehensive rule sets including:
- Enterprise malware indicators
- Ransomware patterns
- APT lateral movement detection
- Webshell detection
- Rootkit detection

### eBPF Kernel Monitoring
Provides real-time visibility into:
- Process execution and termination
- Network connections
- File system access
- System call monitoring

### Honeypot System
Dynamic honeypots that:
- Listen on random ports
- Emulate common services (HTTP, SSH, FTP, Telnet, SMTP)
- Log and analyze attack attempts
- Generate intelligence reports

### Threat Intelligence
Integrates with:
- FireHOL IP blocklists
- AbuseIPDB (optional)
- VirusTotal (optional)

## Troubleshooting

### Common Issues

**eBPF monitoring fails:**
- Ensure kernel version 4.15+
- Install BCC tools correctly
- Run as root

**YARA not found:**
- Install YARA from packages or compile manually
- Ensure yara command is in PATH

**Dashboard won't start:**
- Ensure Go is installed and in PATH
- Check that theProtector.go exists
- Verify port 8082 is available

**Loop mode background service management:**
- Honeypots and eBPF monitoring are started once at initialization
- Services are only restarted if they become inactive
- Check service status with: `sudo ./theProtectorV4.sh status`
- Clean up stuck processes with: `sudo ./theProtectorV4.sh cleanup`

**Permission denied:**
- Most features require root access
- Use sudo for all commands

### Logs and Debugging

Enable verbose logging:
```bash
VERBOSE=true sudo ./theProtectorV4.sh enhanced
```

Check logs:
```bash
sudo ./theProtectorV4.sh logs
```

View alerts:
```bash
sudo ./theProtectorV4.sh alerts
```

### Performance Tuning

For resource-constrained systems:
```bash
PERFORMANCE_MODE=true sudo ./theProtectorV4.sh enhanced
```

## Contributing

TheProtectorV4 is designed to be extensible. Key areas for contribution:

- Additional YARA rules
- New honeypot protocols
- Enhanced threat intelligence sources
- Dashboard features
- Cross-platform support

## License

This project is provided as-is for security research and system administration purposes. Use at your own risk.

## Disclaimer

TheProtectorV4 is a security monitoring tool. While designed to enhance system security, it may produce false positives or impact system performance. Always test in a safe environment before production deployment.

## Support

For issues and questions:
1. Check the logs: `sudo ./theProtectorV4.sh logs`
2. Run diagnostics: `sudo ./theProtectorV4.sh test`
3. Review configuration and dependencies
4. Check system compatibility

## Version History

- **v4.0**: Complete rewrite with eBPF, honeypots, and Go dashboard
- Enhanced threat detection and forensic capabilities
- Improved performance and stability
