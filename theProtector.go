package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type SystemStats struct {
	CPU     float64 `json:"cpu"`
	Memory  float64 `json:"memory"`
	Disk    float64 `json:"disk"`
	Time    int64   `json:"time"`
}

type SecurityStatus struct {
	EBPFMonitoring    bool     `json:"ebpf_monitoring"`
	YARAMalware       bool     `json:"yara_malware"`
	NetworkHoneypots  bool     `json:"network_honeypots"`
	AntiEvasion       bool     `json:"anti_evasion"`
	ThreatIntel       bool     `json:"threat_intel"`
	ContainerSupport  bool     `json:"container_support"`
	ForensicEnabled   bool     `json:"forensic_enabled"`
	APIInterface      bool     `json:"api_interface"`
	ActiveAlerts      []Alert  `json:"active_alerts"`
	LastScan          string   `json:"last_scan"`
}

type Alert struct {
	Level     string `json:"level"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type DashboardData struct {
	SystemStats    []SystemStats  `json:"system_stats"`
	SecurityStatus SecurityStatus `json:"security_status"`
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Allow connections from any origin in development
		},
	}
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
	stats     []SystemStats
	statsMu   sync.RWMutex
)

func main() {
	// Initialize stats slice
	stats = make([]SystemStats, 0, 100)

	// Start background monitoring
	go monitorSystemStats()

	// Setup routes
	http.HandleFunc("/", dashboardHandler)
	http.HandleFunc("/api/stats", statsAPIHandler)
	http.HandleFunc("/api/security", securityAPIHandler)
	http.HandleFunc("/api/run-scan", runScanHandler)
	http.HandleFunc("/ws", wsHandler)
	// Removed static file serving to prevent path traversal vulnerabilities

	// Silent startup - no console output for security
	log.SetOutput(os.Stderr) // Redirect logs to stderr, not stdout
	log.Fatal(http.ListenAndServe(":8082", nil))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	// Embedded HTML template to avoid file system dependencies
	dashboardHTML := `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>theProtector Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #474343ff; color: #fff; }
        .header { background: linear-gradient(135deg, #ba0018 80%, #b80505ff 20%); padding: 20px; text-align: center; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }
        .card { background: #2d3748; border-radius: 8px; padding: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .card h3 { color: #667eea; margin-bottom: 15px; }
        .metric { display: flex; justify-content: space-between; margin: 10px 0; }
        .metric-value { font-weight: bold; color: #48bb78; }
        .alert { background: #742a2a; border-left: 4px solid #fc8181; padding: 10px; margin: 5px 0; border-radius: 4px; }
        .alert.critical { border-left-color: #fc8181; background: #742a2a; }
        .alert.high { border-left-color: #f6ad55; background: #744210; }
        .alert.medium { border-left-color: #68d391; background: #22543d; }
        .status-indicator { display: inline-block; width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }
        .status-active { background: #48bb78; }
        .status-inactive { background: #f56565; }
        .btn { background: #667eea; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; }
        .btn:hover { background: #5a67d8; }
        .chart-container { height: 200px; position: relative; }
        #systemChart { width: 100%; height: 100%; }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <div class="header">
        <h1>🛡️ Ghost Sentinel Dashboard</h1>
        <p>Advanced Security Monitoring Suite v2.3</p>
    </div>
    
    <div class="container">
        <div class="grid">
            <div class="card">
                <h3>System Metrics</h3>
                <div class="chart-container">
                    <canvas id="systemChart"></canvas>
                </div>
                <div class="metric">
                    <span>CPU Usage:</span>
                    <span class="metric-value" id="cpu">0%</span>
                </div>
                <div class="metric">
                    <span>Memory Usage:</span>
                    <span class="metric-value" id="memory">0%</span>
                </div>
                <div class="metric">
                    <span>Disk Usage:</span>
                    <span class="metric-value" id="disk">0%</span>
                </div>
            </div>
            
            <div class="card">
                <h3>Security Status</h3>
                <div class="metric">
                    <span><span class="status-indicator" id="ebpf-status"></span>eBPF Monitoring:</span>
                    <span id="ebpf-text">Checking...</span>
                </div>
                <div class="metric">
                    <span><span class="status-indicator" id="yara-status"></span>YARA Malware:</span>
                    <span id="yara-text">Checking...</span>
                </div>
                <div class="metric">
                    <span><span class="status-indicator" id="honeypot-status"></span>Honeypots:</span>
                    <span id="honeypot-text">Checking...</span>
                </div>
                <div class="metric">
                    <span><span class="status-indicator" id="forensic-status"></span>Forensics:</span>
                    <span id="forensic-text">Checking...</span>
                </div>
                <button class="btn" onclick="runScan()">Run Security Scan</button>
            </div>
            
            <div class="card">
                <h3>Active Alerts</h3>
                <div id="alerts-container">
                    <p>Loading alerts...</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        let chart;
        let socket;
        
        function initChart() {
            const ctx = document.getElementById('systemChart').getContext('2d');
            chart = new Chart(ctx, {
                type: 'line',
                data: {
                    labels: [],
                    datasets: [{
                        label: 'CPU %',
                        data: [],
                        borderColor: '#667eea',
                        backgroundColor: 'rgba(102, 126, 234, 0.1)',
                        tension: 0.4
                    }, {
                        label: 'Memory %',
                        data: [],
                        borderColor: '#48bb78',
                        backgroundColor: 'rgba(72, 187, 120, 0.1)',
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    scales: {
                        y: { beginAtZero: true, max: 100 }
                    },
                    plugins: { legend: { display: true } }
                }
            });
        }
        
        function connectWebSocket() {
            socket = new WebSocket('ws://localhost:8082/ws');
            socket.onmessage = function(event) {
                const data = JSON.parse(event.data);
                updateMetrics(data);
                updateChart(data);
            };
            socket.onclose = function() {
                setTimeout(connectWebSocket, 5000);
            };
        }
        
        function updateMetrics(data) {
            document.getElementById('cpu').textContent = data.cpu.toFixed(1) + '%';
            document.getElementById('memory').textContent = data.memory.toFixed(1) + '%';
            document.getElementById('disk').textContent = data.disk.toFixed(1) + '%';
        }
        
        function updateChart(data) {
            const now = new Date().toLocaleTimeString();
            chart.data.labels.push(now);
            chart.data.datasets[0].data.push(data.cpu);
            chart.data.datasets[1].data.push(data.memory);
            
            if (chart.data.labels.length > 20) {
                chart.data.labels.shift();
                chart.data.datasets[0].data.shift();
                chart.data.datasets[1].data.shift();
            }
            chart.update('none');
        }
        
        function loadSecurityStatus() {
            fetch('/api/security')
                .then(response => response.json())
                .then(data => {
                    updateStatus('ebpf', data.ebpf_monitoring);
                    updateStatus('yara', data.yara_malware);
                    updateStatus('honeypot', data.network_honeypots);
                    updateStatus('forensic', data.forensic_enabled);
                    displayAlerts(data.active_alerts);
                });
        }
        
        function updateStatus(type, active) {
            const indicator = document.getElementById(type + '-status');
            const text = document.getElementById(type + '-text');
            if (active) {
                indicator.className = 'status-indicator status-active';
                text.textContent = 'Active';
            } else {
                indicator.className = 'status-indicator status-inactive';
                text.textContent = 'Inactive';
            }
        }
        
        function displayAlerts(alerts) {
            const container = document.getElementById('alerts-container');
            if (alerts.length === 0) {
                container.innerHTML = '<p>No active alerts</p>';
                return;
            }
            
            container.innerHTML = alerts.map(alert => 
                '<div class="alert ' + alert.level.toLowerCase() + '">' +
                '<strong>' + alert.level + '</strong>: ' + alert.message +
                '<div style="font-size: 0.8em; margin-top: 5px;">' + alert.timestamp + '</div>' +
                '</div>'
            ).join('');
        }
        
        function runScan() {
            fetch('/api/run-scan', { method: 'POST' })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        alert('Security scan started successfully!');
                        setTimeout(loadSecurityStatus, 2000);
                    }
                });
        }
        
        // Initialize
        window.onload = function() {
            initChart();
            connectWebSocket();
            loadSecurityStatus();
            setInterval(loadSecurityStatus, 30000);
        };
    </script>
</body>
</html>`
	
	tmpl := template.Must(template.New("dashboard").Parse(dashboardHTML))
	tmpl.Execute(w, nil)
}

func statsAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	statsMu.RLock()
	defer statsMu.RUnlock()

	response := map[string]interface{}{
		"stats": stats,
	}
	json.NewEncoder(w).Encode(response)
}

func securityAPIHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	status := getSecurityStatus()
	json.NewEncoder(w).Encode(status)
}

func runScanHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Start scan in background without exposing output for security
	go func() {
		cmd := exec.Command("./theProtectorV4.sh", "enhanced")
		cmd.Run() // Discard output for security
	}()

	response := map[string]interface{}{
		"success": true,
		"message": "Security scan started in background",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
// WebSocket handler - minimal logging for security
func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		// Silent failure for security
		return
	}

	defer conn.Close()

	clientsMu.Lock()
	clients[conn] = true
	clientsMu.Unlock()

	defer func() {
		clientsMu.Lock()
		delete(clients, conn)
		clientsMu.Unlock()
	}()

	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func monitorSystemStats() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		stat := getSystemStats()

		statsMu.Lock()
		stats = append(stats, stat)
		if len(stats) > 100 {
			stats = stats[1:]
		}
		statsMu.Unlock()

		clientsMu.Lock()
		for client := range clients {
			if err := client.WriteJSON(stat); err != nil {
				client.Close()
				delete(clients, client)
			}
		}
		clientsMu.Unlock()
	}
}

func getSystemStats() SystemStats {
	now := time.Now()


	cpu := getCPUUsage()


	mem := getMemoryUsage()


	disk := getDiskUsage()

	return SystemStats{
		CPU:    cpu,
		Memory: mem,
		Disk:   disk,
		Time:   now.Unix(),
	}
}

func getCPUUsage() float64 {
	cmd := exec.Command("bash", "-c", "top -bn1 | grep 'Cpu(s)' | sed 's/.*, *\\([0-9.]*\\)%* id.*/\\1/' | awk '{print 100 - $1}'")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	usage, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
	if err != nil {
		return 0
	}

	return usage
}

func getMemoryUsage() float64 {
	cmd := exec.Command("bash", "-c", "free | grep Mem | awk '{printf \"%.2f\", $3/$2 * 100.0}'")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	usage, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
	if err != nil {
		return 0
	}

	return usage
}

func getDiskUsage() float64 {
	cmd := exec.Command("bash", "-c", "df / | tail -1 | awk '{print $5}' | sed 's/%//'")
	output, err := cmd.Output()
	if err != nil {
		return 0
	}

	usage, err := strconv.ParseFloat(strings.TrimSpace(string(output)), 64)
	if err != nil {
		return 0
	}

	return usage
}

func getSecurityStatus() SecurityStatus {

	scriptPath := "./theProtectorV4.sh"
	status := SecurityStatus{
		LastScan: time.Now().Format("2006-01-02 15:04:05"),
	}

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		return status
	}


	jsonFile := os.Getenv("HOME") + "/.ghost-sentinel/logs/latest_scan.json"
	if _, err := os.Stat(jsonFile); os.IsNotExist(err) {
		// Fallback to system log directory
		jsonFile = "/var/log/ghost-sentinel/latest_scan.json"
	}
	if data, err := os.ReadFile(jsonFile); err == nil {
		var jsonData map[string]interface{}
		if json.Unmarshal(data, &jsonData) == nil {
			if features, ok := jsonData["features"].(map[string]interface{}); ok {
				if ebpf, ok := features["ebpf_monitoring"].(string); ok {
					status.EBPFMonitoring = ebpf == "true"
				}
				if honeypots, ok := features["honeypots"].(string); ok {
					status.NetworkHoneypots = honeypots == "true"
				}
				if yara, ok := features["yara_scanning"].(string); ok {
					status.YARAMalware = yara == "true"
				}
				if api, ok := features["api_server"].(string); ok {
					status.APIInterface = api == "true"
				}
			}
		
			status.AntiEvasion = checkAntiEvasionEnabled(jsonData)
			status.ThreatIntel = checkThreatIntelEnabled(jsonData)
			status.ForensicEnabled = checkForensicsEnabled(jsonData)
		}
	}


	if !status.EBPFMonitoring {
		status.EBPFMonitoring = checkProcessRunning("ebpf_monitor")
	}
	if !status.NetworkHoneypots {
		status.NetworkHoneypots = checkHoneypotsRunning()
	}
	if !status.YARAMalware {
		status.YARAMalware = checkCommandAvailable("yara")
	}

	// Check for container support
	status.ContainerSupport = checkContainerEnvironment()

	// Get active alerts
	status.ActiveAlerts = getActiveAlerts()

	return status
}

func checkProcessRunning(processName string) bool {
	cmd := exec.Command("pgrep", "-f", processName)
	return cmd.Run() == nil
}

func checkHoneypotsRunning() bool {
	
	logsDir := os.Getenv("HOME") + "/.ghost-sentinel/logs"
	if _, err := os.Stat(logsDir + "/honeypot.pids"); os.IsNotExist(err) {
		return false
	}
	return true
}

func checkCommandAvailable(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

func checkContainerEnvironment() bool {
	
	indicators := []string{
		"/.dockerenv",
		"/run/.containerenv",
		"/proc/1/cgroup",
	}

	for _, indicator := range indicators {
		if _, err := os.Stat(indicator); err == nil {
			return true
		}
	}

	return false
}

func checkThreatIntelFiles() bool {
	threatFiles := []string{
		os.Getenv("HOME") + "/.ghost-sentinel/logs/threat_intel/malicious_ips.txt",
		os.Getenv("HOME") + "/.ghost-sentinel/logs/threat_intel/.last_update",
	}

	for _, file := range threatFiles {
		if _, err := os.Stat(file); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func checkAntiEvasionEnabled(jsonData map[string]interface{}) bool {
	if features, ok := jsonData["features"].(map[string]interface{}); ok {
		if antiEvasion, ok := features["anti_evasion"].(string); ok {
			return antiEvasion == "true"
		}
	}
	if env, ok := jsonData["environment"].(map[string]interface{}); ok {
		if antiEvasion, ok := env["anti_evasion"].(string); ok {
			return antiEvasion == "true"
		}
	}
	return false
}

func checkThreatIntelEnabled(jsonData map[string]interface{}) bool {
	if features, ok := jsonData["features"].(map[string]interface{}); ok {
		if threatIntel, ok := features["threat_intelligence"].(string); ok {
			return threatIntel == "true"
		}
	}
	if env, ok := jsonData["environment"].(map[string]interface{}); ok {
		if threatIntel, ok := env["threat_intel"].(string); ok {
			return threatIntel == "true"
		}
	}
	return checkThreatIntelFiles()
}

func checkForensicsEnabled(jsonData map[string]interface{}) bool {
	if features, ok := jsonData["features"].(map[string]interface{}); ok {
		if forensics, ok := features["forensic_analysis"].(string); ok {
			return forensics == "true"
		}
	}
	if env, ok := jsonData["environment"].(map[string]interface{}); ok {
		if forensics, ok := env["forensics"].(string); ok {
			return forensics == "true"
		}
	}
	// Check for quarantine directory
	if _, err := os.Stat(os.Getenv("HOME") + "/.ghost-sentinel/logs/quarantine"); os.IsNotExist(err) {
		return false
	}
	return true
}

func getActiveAlerts() []Alert {
	alerts := []Alert{}

	// Check alert files --- Keep it Simple ---
	alertDir := os.Getenv("HOME") + "/.ghost-sentinel/logs/alerts"
	if _, err := os.Stat(alertDir); os.IsNotExist(err) {
		// Fallback to system log directory
		alertDir = "/var/log/ghost-sentinel/alerts"
	}
	if _, err := os.Stat(alertDir); os.IsNotExist(err) {
		return alerts
	}

	files, err := filepath.Glob(filepath.Join(alertDir, "*.log"))
	if err != nil {
		return alerts
	}

	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		lines := strings.Split(string(content), "\n")
		for _, line := range lines {
			// Check for LEVEL format: [LEVEL:1] for CRITICAL, [LEVEL:2] for HIGH
			if strings.Contains(line, "[LEVEL:") {
				alert := Alert{
					Level:     "HIGH",
					Message:   strings.TrimSpace(line),
					Timestamp: time.Now().Format("2006-01-02 15:04:05"),
				}
				
				// Extract level number
				if strings.Contains(line, "[LEVEL:1]") {
					alert.Level = "CRITICAL"
				} else if strings.Contains(line, "[LEVEL:2]") {
					alert.Level = "HIGH"
				} else if strings.Contains(line, "[LEVEL:3]") {
					alert.Level = "MEDIUM"
				} else if strings.Contains(line, "[LEVEL:4]") {
					alert.Level = "LOW"
				}
				
				alerts = append(alerts, alert)
			}
		}
	}

	return alerts
}
