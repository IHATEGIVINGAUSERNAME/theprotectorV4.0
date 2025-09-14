package main

import (
	"encoding/json"
	"fmt"
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
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Ghost Sentinel Dashboard starting on http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/dashboard.html"))
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


	cmd := exec.Command("./theprotectorV4.0.sh", "enhanced")
	output, err := cmd.CombinedOutput()

	response := map[string]interface{}{
		"success": err == nil,
		"output":  string(output),
	}

	if err != nil {
		response["error"] = err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
// WebSocket is just a copy and paste from previous project with minor adjustments
func wsHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
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
	ticker := time.NewTicker(2 * time.Second)
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

	scriptPath := "./theprotectorV4.0.sh"
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
			if strings.Contains(line, "[CRITICAL]") || strings.Contains(line, "[HIGH]") {
				alert := Alert{
					Level:     "HIGH",
					Message:   strings.TrimSpace(line),
					Timestamp: time.Now().Format("2006-01-02 15:04:05"),
				}
				if strings.Contains(line, "[CRITICAL]") {
					alert.Level = "CRITICAL"
				}
				alerts = append(alerts, alert)
			}
		}
	}

	return alerts
}
