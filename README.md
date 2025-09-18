# theProtector v4 - Advanced Security Monitoring Suite

Ghost Sentinel is a comprehensive, enterprise-grade security monitoring system designed for Linux environments. It combines traditional security monitoring with advanced threat detection capabilities including eBPF kernel monitoring, YARA malware scanning, dynamic honeypots, and forensic analysis.

## Components

### 1. Core Security Monitor (`theProtectorV4.sh`)
A production-hardened bash script providing comprehensive security monitoring capabilities.

### 2. Web Dashboard (`theProtector.go`)
A Go-based web application providing real-time monitoring and control interface.

## Features

### Core Security Monitoring
- **Network Monitoring**: Advanced network traffic analysis with anti-evasion detection
- **Process Monitoring**: Suspicious process detection and analysis
- **File System Monitoring**: Real-time file integrity monitoring with YARA malware detection
- **User Account Monitoring**: New user detection and privilege escalation monitoring
- **Memory Analysis**: High memory usage detection and analysis
- **Rootkit Detection**: Advanced rootkit and kernel malware detection

### Advanced Threat Detection
- **eBPF Kernel Monitoring**: Deep kernel-level observability using eBPF/BCC tools
- **YARA Malware Scanning**: Enterprise-grade malware detection with custom YARA rules
- **Dynamic Honeypots**: Multi-protocol honeypot system with intelligence gathering
- **Threat Intelligence**: Automated threat intelligence updates and correlation
- **Anti-Evasion Detection**: Detection of common evasion techniques (LD_PRELOAD, etc.)

### Enterprise Features
- **Container Support**: Native support for Docker and containerized environments
- **Forensic Analysis**: Comprehensive file quarantine with metadata preservation
- **JSON API**: Structured output for integration with SIEM systems
- **Systemd Integration**: Native systemd service support
- **Performance Mode**: Optimized scanning for high-performance environments

## Installation

### Prerequisites
- Linux operating system
- Bash shell
- Root privileges recommended for full functionality
- Go 1.16+ (for dashboard)
- Optional: YARA, BCC/eBPF tools, jq, inotify-tools

### Basic Installation
```bash
# Clone or download the scripts
# Make executable
chmod +x theProtectorV4.sh

# Run initial setup
sudo ./theProtectorV4.sh install
```

### Advanced Installation with Dashboard
```bash
# Install Go if not present
# Build dashboard
go build -o theProtector theProtector.go

# Start dashboard
./theProtector &
```

## Usage

### Command Line Interface

#### Basic Scan
```bash
sudo ./theProtectorV4.sh
```

#### Enhanced Scan with All Features
```bash
sudo ./theProtectorV4.sh enhanced
```

#### Specific Monitoring Modes
```bash
# Performance optimized scan
sudo ./theProtectorV4.sh performance

# Test mode (safe for testing)
sudo ./theProtectorV4.sh test

# Baseline creation/update
sudo ./theProtectorV4.sh baseline
```

#### Management Commands
```bash
# Install as system service
sudo ./theProtectorV4.sh install

# View logs
sudo ./theProtectorV4.sh logs

# View alerts
sudo ./theProtectorV4.sh alerts

# JSON output
sudo ./theProtectorV4.sh json

# Status check
sudo ./theProtectorV4.sh status
```

#### Advanced Features
```bash
# Start eBPF monitoring
sudo ./theProtectorV4.sh ebpf

# Start honeypots
sudo ./theProtectorV4.sh honeypot

# YARA file scanning
sudo ./theProtectorV4.sh yara

# Update threat intelligence
sudo ./theProtectorV4.sh update
```

#### Additional Commands
```bash
# Start web dashboard
sudo ./theProtectorV4.sh dashboard

# Cleanup and fix issues
sudo ./theProtectorV4.sh cleanup

# Check integrity
sudo ./theProtectorV4.sh integrity

# Reset integrity hash
sudo ./theProtectorV4.sh reset-integrity

# Fix hostname issues
sudo ./theProtectorV4.sh fix-hostname

# Create systemd service
sudo ./theProtectorV4.sh systemd

# Complete uninstall
sudo ./theProtectorV4.sh uninstall
```

### Web Dashboard

#### Starting the Dashboard
```bash
# Start the web interface (Go must be installed)
sudo ./theProtectorV4.sh dashboard

# Or run directly with Go
go run theProtector.go
```

The dashboard will be available at `http://localhost:8082`

#### Dashboard Features
- Real-time system statistics (CPU, Memory, Disk)
- Security status overview with live indicators
- Active alerts display with severity levels
- Remote scan initiation capability
- WebSocket-based live updates
- Embedded HTML interface (no external file dependencies)

## Configuration

### Configuration File
The system uses `sentinel.conf` for configuration. Edit with:
```bash
./theProtectorV4.sh config
```

### Environment Variables
- `LOG_DIR`: Log directory (auto-detected based on permissions)
- `CONFIG_FILE`: Configuration file path
- `JSON_OUTPUT_FILE`: JSON output file location

## Output Formats

### Console Output
Color-coded security summary with:
- Scan duration
- Module execution status
- Alert counts by severity
- Active features status

### JSON Output
Structured JSON output available at:
- User mode: `~/.ghost-sentinel/logs/latest_scan.json`
- Root mode: `/var/log/ghost-sentinel/latest_scan.json`

Contains:
- Scan metadata and timing
- Security features status
- Alert details with severity levels
- System information and environment detection

### Log Files
- `sentinel.log`: General operation logs
- `alerts/YYYYMMDD.log`: Daily security alerts
- `ebpf_events.log`: eBPF monitoring events (if enabled)
- `honeypot.log`: Honeypot activity logs (if enabled)
- `quarantine/`: Quarantined files with forensic data

## Security Features

### Threat Detection
- Malware pattern matching with YARA
- Suspicious network connections
- Privilege escalation attempts
- Rootkit indicators
- Memory-based attacks

### Anti-Evasion
- LD_PRELOAD detection
- Process hiding detection
- Network tool inconsistency checking
- Kernel symbol analysis

### Forensic Capabilities
- File quarantine with metadata preservation
- Hash calculation for integrity
- String analysis
- YARA signature matching

## API Endpoints (Dashboard)

### REST API
- `GET /api/stats`: System statistics
- `GET /api/security`: Security status
- `POST /api/run-scan`: Initiate security scan

### WebSocket
- `/ws`: Real-time system statistics streaming

## Integration

### SIEM Integration
JSON output can be integrated with SIEM systems like:
- ELK Stack (Elasticsearch, Logstash, Kibana)
- Splunk
- IBM QRadar

### Monitoring Systems
- Prometheus metrics export (planned)
- Grafana dashboards (planned)

## Troubleshooting

### Common Issues

#### Permission Errors
```bash
# Run with appropriate permissions
sudo ./theProtectorV4.sh

# For user-level monitoring
./theProtectorV4.sh
```

#### Missing Dependencies
```bash
# Install recommended packages
sudo apt-get install yara python3-bcc jq inotify-tools  # Debian/Ubuntu
sudo dnf install yara bcc jq inotify-tools            # Fedora/RHEL
```

#### Dashboard Not Starting
```bash
# Check Go installation
go version

# Install Go if missing
sudo apt-get install golang-go  # Debian/Ubuntu
sudo dnf install golang         # Fedora/RHEL

# Check if theProtector.go exists in same directory
ls -la theProtector.go

# Run dashboard command
sudo ./theProtectorV4.sh dashboard
```

#### eBPF Not Working
- Requires kernel 4.4+
- May need BCC tools installation
- Check kernel configuration for eBPF support

### Debug Mode
```bash
# Enable verbose logging
./theProtectorV4.sh --verbose enhanced
```

## Security Considerations

### Running as Root
- Recommended for full system visibility
- Automatic privilege detection and adjustment
- Secure directory permissions (700)

### Network Security
- Honeypots run on dynamic ports (if enabled)
- No external network exposure by default
- Dashboard binds to localhost only (127.0.0.1:8082)
- Embedded HTML template prevents path traversal attacks

### Data Protection
- Sensitive logs encrypted where possible
- Automatic log rotation
- Secure quarantine directory permissions

## Contributing

### Development Setup
```bash
# Fork and clone
git clone https://github.com/your-repo/ghost-sentinel.git
cd ghost-sentinel

# Make changes
# Test thoroughly
# Submit pull request
```

### Code Standards
- Bash: Follow Google Shell Style Guide
- Go: Standard Go formatting and conventions
- Security: Input validation and secure coding practices

## License

This project is free and provided as-is for security research and monitoring purposes. Use responsibly and in compliance with applicable laws and regulations.

## Disclaimer

Ghost Sentinel is designed for security monitoring and research. Users are responsible for ensuring compliance with local laws and regulations regarding security monitoring and data collection.

## Version History

### v4 (Current)
- Enhanced eBPF monitoring capabilities
- Dynamic honeypot system with multi-protocol support
- Advanced YARA rules for enterprise threats
- Embedded web dashboard with real-time monitoring
- Improved threat intelligence integration
- Enhanced forensic analysis and file quarantine
- Better container and VM environment detection
- Arithmetic validation fixes and stability improvements
- Advanced anti-evasion detection
- Comprehensive uninstall functionality
- Enhanced systemd integration

### v2.3 (Previous)
- Enhanced eBPF monitoring capabilities
- Dynamic honeypot system with multi-protocol support
- Advanced YARA rules for enterprise threats
- Embedded web dashboard with real-time monitoring
- Improved threat intelligence integration
- Enhanced forensic analysis and file quarantine
- Better container and VM environment detection
- Arithmetic validation fixes and stability improvements

### v2.2
- Container support
- Performance optimizations
- JSON API
- Systemd integration

### v2.1
- YARA malware detection
- Anti-evasion detection
- Enhanced logging

### v2.0
- Complete rewrite with modular architecture
- Advanced threat detection
- Cross-platform compatibility improvements
