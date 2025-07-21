package main

import (
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"
)

// VerificationResult represents the result of a verification command
type VerificationResult struct {
	Command     string
	RawOutput   string
	ParsedData  interface{}
	Summary     string
	Annotations []string
}

// ParseVerificationOutput parses the output of a verification command
func ParseVerificationOutput(command, output string) *VerificationResult {
	result := &VerificationResult{
		Command:   command,
		RawOutput: output,
	}

	// Determine which parser to use based on the command
	if strings.Contains(command, "show ip interface brief") {
		result.ParsedData = parseIPInterfaceBrief(output)
		result.Summary = generateInterfaceSummary(result.ParsedData)
	} else if strings.Contains(command, "show vlan brief") {
		result.ParsedData = parseVLANBrief(output)
		result.Summary = generateVLANSummary(result.ParsedData)
	} else if strings.Contains(command, "show ip route") {
		if strings.Contains(command, "show ip route static") {
			result.ParsedData = parseIPRouteStatic(output)
		} else {
			result.ParsedData = parseIPRoute(output)
		}
		result.Summary = generateRouteSummary(result.ParsedData)
	} else if strings.Contains(command, "show ip ospf neighbor") {
		result.ParsedData = parseOSPFNeighbor(output)
		result.Summary = generateOSPFNeighborSummary(result.ParsedData)
	} else if strings.Contains(command, "show ip eigrp neighbors") {
		result.ParsedData = parseEIGRPNeighbors(output)
		result.Summary = generateEIGRPNeighborSummary(result.ParsedData)
	} else if strings.Contains(command, "show running-config") {
		// For running-config, we just provide annotations about key sections
		result.Annotations = analyzeRunningConfig(output)
	} else {
		// For unrecognized commands, just return the raw output
		result.Summary = "Unrecognized command, showing raw output"
	}

	return result
}

// PrintVerificationResult prints the verification result in a user-friendly format
func PrintVerificationResult(result *VerificationResult) {
	log.Printf("📋 Command: %s", result.Command)
	
	if result.Summary != "" {
		log.Printf("📊 Summary: %s", result.Summary)
	}
	
	if len(result.Annotations) > 0 {
		log.Println("📝 Annotations:")
		for _, annotation := range result.Annotations {
			log.Printf("  - %s", annotation)
		}
	}
	
	// Always print the raw output for reference
	log.Println(result.RawOutput)
}

// RunEnhancedVerificationCheck parses and analyzes command outputs
// This function is exported to maintain consistency with other command functions
func RunEnhancedVerificationCheck(creds *VaultCredentials, command string) {
	log.Printf("📋 Running verification command: %s", command)
	client, err := NewRealSSHClient(creds.Host, creds.Username, creds.Password)
	if err != nil {
		log.Printf("❌ ERROR: Failed to connect to %s: %v", creds.Host, err)
		return
	}
	defer client.Close()

	// Execute the command
	output, err := client.Run(
		"enable", 
		creds.EnableSecret, 
		"terminal length 0", 
		command, 
		"exit",
	)
	if err != nil {
		log.Printf("❌ ERROR: Command execution failed: %v", err)
		return
	}

	// Clean the raw output
	cleanedOutput := cleanShellOutput(output)
	
	// Parse and analyze the output
	result := ParseVerificationOutput(command, cleanedOutput)
	
	// Print the result
	PrintVerificationResult(result)
}

// GetLastLogs retrieves and displays the last 15 logs from a device
// It also saves the logs to a file named "device_logs_{hostname}_{timestamp}.txt"
func GetLastLogs(creds *VaultCredentials) {
	log.Printf("📋 Retrieving last 15 logs from device %s", creds.Host)
	client, err := NewRealSSHClient(creds.Host, creds.Username, creds.Password)
	if err != nil {
		log.Printf("❌ ERROR: Failed to connect to %s: %v", creds.Host, err)
		return
	}
	defer client.Close()

	// Execute the command to get logs
	output, err := client.Run(
		"enable", 
		creds.EnableSecret, 
		"terminal length 0", 
		"show logging", 
		"exit",
	)
	if err != nil {
		log.Printf("❌ ERROR: Command execution failed: %v", err)
		return
	}

	// Clean the raw output
	cleanedOutput := cleanShellOutput(output)
	
	// Extract the last 15 log entries
	logs := extractLastLogs(cleanedOutput, 15)
	
	// Create a timestamp for the log file
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	
	// Create a sanitized hostname for the filename (remove any invalid characters)
	hostname := strings.ReplaceAll(creds.Host, ":", "_")
	hostname = strings.ReplaceAll(hostname, "/", "_")
	hostname = strings.ReplaceAll(hostname, "\\", "_")
	
	// Create the log file
	filename := fmt.Sprintf("device_logs_%s_%s.txt", hostname, timestamp)
	file, err := os.Create(filename)
	if err != nil {
		log.Printf("❌ ERROR: Failed to create log file: %v", err)
	} else {
		defer file.Close()
		
		// Write a header to the file
		fmt.Fprintf(file, "=== LOGS FROM DEVICE %s ===\n", creds.Host)
		fmt.Fprintf(file, "=== Retrieved at: %s ===\n\n", time.Now().Format("2006-01-02 15:04:05"))
		
		// Write each log entry to the file
		for i, logEntry := range logs {
			fmt.Fprintf(file, "%d: %s\n", i+1, logEntry)
		}
		
		log.Printf("✅ Logs saved to file: %s", filename)
	}
	
	// Print a clear header for the logs in the console
	log.Println("==================================================")
	log.Printf("📜 LAST 15 LOGS FROM DEVICE %s:", creds.Host)
	log.Println("==================================================")
	
	// Print each log entry with a clear format
	for i, logEntry := range logs {
		log.Printf("%2d: %s", i+1, logEntry)
	}
	
	log.Println("==================================================")
	log.Printf("✅ End of logs from device %s", creds.Host)
	log.Println("==================================================")
}

// Interface-related parsing functions

type InterfaceStatus struct {
	Name      string
	IPAddress string
	OK        string
	Method    string
	Status    string
	Protocol  string
}

func parseIPInterfaceBrief(output string) []InterfaceStatus {
	var interfaces []InterfaceStatus
	
	// Skip the header line
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return interfaces
	}
	
	// Process each line after the header
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		
		// Split the line into fields
		fields := regexp.MustCompile(`\s+`).Split(line, 6)
		if len(fields) < 6 {
			continue
		}
		
		interfaces = append(interfaces, InterfaceStatus{
			Name:      fields[0],
			IPAddress: fields[1],
			OK:        fields[2],
			Method:    fields[3],
			Status:    fields[4],
			Protocol:  fields[5],
		})
	}
	
	return interfaces
}

func generateInterfaceSummary(data interface{}) string {
	interfaces, ok := data.([]InterfaceStatus)
	if !ok {
		return "Invalid interface data"
	}
	
	var upCount, downCount, adminDownCount int
	var ipCount int
	
	for _, iface := range interfaces {
		if iface.Status == "up" && iface.Protocol == "up" {
			upCount++
		} else if iface.Status == "administratively down" {
			adminDownCount++
		} else {
			downCount++
		}
		
		if iface.IPAddress != "unassigned" {
			ipCount++
		}
	}
	
	return fmt.Sprintf("Total interfaces: %d | Up: %d | Down: %d | Admin down: %d | With IP: %d",
		len(interfaces), upCount, downCount, adminDownCount, ipCount)
}

// VLAN-related parsing functions

type VLANStatus struct {
	ID     string
	Name   string
	Status string
	Ports  []string
}

func parseVLANBrief(output string) []VLANStatus {
	var vlans []VLANStatus
	
	// Skip the header line
	lines := strings.Split(output, "\n")
	if len(lines) < 2 {
		return vlans
	}
	
	// Process each line after the header
	for i := 1; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		
		// Split the line into fields
		fields := regexp.MustCompile(`\s+`).Split(line, 4)
		if len(fields) < 3 {
			continue
		}
		
		var ports []string
		if len(fields) >= 4 {
			portsStr := fields[3]
			ports = strings.Split(portsStr, ", ")
		}
		
		vlans = append(vlans, VLANStatus{
			ID:     fields[0],
			Name:   fields[1],
			Status: fields[2],
			Ports:  ports,
		})
	}
	
	return vlans
}

func generateVLANSummary(data interface{}) string {
	vlans, ok := data.([]VLANStatus)
	if !ok {
		return "Invalid VLAN data"
	}
	
	var activeCount, inactiveCount, unusedCount int
	
	for _, vlan := range vlans {
		if vlan.Status == "active" {
			if len(vlan.Ports) > 0 {
				activeCount++
			} else {
				unusedCount++
			}
		} else {
			inactiveCount++
		}
	}
	
	return fmt.Sprintf("Total VLANs: %d | Active with ports: %d | Active without ports: %d | Inactive: %d",
		len(vlans), activeCount, unusedCount, inactiveCount)
}

// Route-related parsing functions

type Route struct {
	Type       string
	Network    string
	Mask       string
	NextHop    string
	AdminDist  string
	Metric     string
	Interface  string
}

func parseIPRoute(output string) []Route {
	var routes []Route
	
	// Process each line
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Codes:") || strings.HasPrefix(line, "Gateway") {
			continue
		}
		
		// Extract route information using regex
		re := regexp.MustCompile(`([A-Z*]+)\s+(\d+\.\d+\.\d+\.\d+)/(\d+)(?:\s+\[(\d+)/(\d+)\])?\s+(?:via\s+(\d+\.\d+\.\d+\.\d+))?,?\s*(\S+)?`)
		matches := re.FindStringSubmatch(line)
		if len(matches) < 3 {
			continue
		}
		
		route := Route{
			Type:    matches[1],
			Network: matches[2],
			Mask:    matches[3],
		}
		
		if len(matches) >= 5 {
			route.AdminDist = matches[4]
			route.Metric = matches[5]
		}
		
		if len(matches) >= 7 {
			route.NextHop = matches[6]
		}
		
		if len(matches) >= 8 {
			route.Interface = matches[7]
		}
		
		routes = append(routes, route)
	}
	
	return routes
}

func parseIPRouteStatic(output string) []Route {
	// For static routes, we can reuse the general route parser
	return parseIPRoute(output)
}

func generateRouteSummary(data interface{}) string {
	routes, ok := data.([]Route)
	if !ok {
		return "Invalid route data"
	}
	
	// Count routes by type
	typeCounts := make(map[string]int)
	for _, route := range routes {
		typeCounts[route.Type]++
	}
	
	// Build summary string
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Total routes: %d | ", len(routes)))
	
	for routeType, count := range typeCounts {
		summary.WriteString(fmt.Sprintf("%s: %d | ", routeType, count))
	}
	
	// Remove trailing separator
	summaryStr := summary.String()
	if len(summaryStr) > 2 {
		summaryStr = summaryStr[:len(summaryStr)-3]
	}
	
	return summaryStr
}

// OSPF-related parsing functions

type OSPFNeighbor struct {
	ID        string
	Priority  string
	State     string
	DeadTime  string
	Address   string
	Interface string
}

func parseOSPFNeighbor(output string) []OSPFNeighbor {
	var neighbors []OSPFNeighbor
	
	// Process each line
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Neighbor ID") {
			continue
		}
		
		// Extract neighbor information using regex
		re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\S+)/(\S+)\s+(\d+:\d+:\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+(\S+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) < 8 {
			continue
		}
		
		neighbors = append(neighbors, OSPFNeighbor{
			ID:        matches[1],
			Priority:  matches[2],
			State:     matches[3],
			DeadTime:  matches[5],
			Address:   matches[6],
			Interface: matches[7],
		})
	}
	
	return neighbors
}

func generateOSPFNeighborSummary(data interface{}) string {
	neighbors, ok := data.([]OSPFNeighbor)
	if !ok {
		return "Invalid OSPF neighbor data"
	}
	
	if len(neighbors) == 0 {
		return "No OSPF neighbors found"
	}
	
	// Count neighbors by state
	stateCounts := make(map[string]int)
	for _, neighbor := range neighbors {
		stateCounts[neighbor.State]++
	}
	
	// Build summary string
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Total OSPF neighbors: %d | ", len(neighbors)))
	
	for state, count := range stateCounts {
		summary.WriteString(fmt.Sprintf("%s: %d | ", state, count))
	}
	
	// Remove trailing separator
	summaryStr := summary.String()
	if len(summaryStr) > 2 {
		summaryStr = summaryStr[:len(summaryStr)-3]
	}
	
	return summaryStr
}

// EIGRP-related parsing functions

type EIGRPNeighbor struct {
	Address    string
	Interface  string
	HoldTime   string
	Uptime     string
	SRTT       string
	RTO        string
	Q          string
	Seq        string
}

func parseEIGRPNeighbors(output string) []EIGRPNeighbor {
	var neighbors []EIGRPNeighbor
	
	// Process each line
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "H") || strings.HasPrefix(line, "EIGRP") {
			continue
		}
		
		// Extract neighbor information using regex
		re := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)`)
		matches := re.FindStringSubmatch(line)
		if len(matches) < 9 {
			continue
		}
		
		neighbors = append(neighbors, EIGRPNeighbor{
			Address:   matches[1],
			Interface: matches[2],
			HoldTime:  matches[3],
			Uptime:    matches[4],
			SRTT:      matches[5],
			RTO:       matches[6],
			Q:         matches[7],
			Seq:       matches[8],
		})
	}
	
	return neighbors
}

func generateEIGRPNeighborSummary(data interface{}) string {
	neighbors, ok := data.([]EIGRPNeighbor)
	if !ok {
		return "Invalid EIGRP neighbor data"
	}
	
	if len(neighbors) == 0 {
		return "No EIGRP neighbors found"
	}
	
	// Count neighbors by interface
	interfaceCounts := make(map[string]int)
	for _, neighbor := range neighbors {
		interfaceCounts[neighbor.Interface]++
	}
	
	// Build summary string
	var summary strings.Builder
	summary.WriteString(fmt.Sprintf("Total EIGRP neighbors: %d | By interface: ", len(neighbors)))
	
	for iface, count := range interfaceCounts {
		summary.WriteString(fmt.Sprintf("%s: %d, ", iface, count))
	}
	
	// Remove trailing separator
	summaryStr := summary.String()
	if len(summaryStr) > 2 {
		summaryStr = summaryStr[:len(summaryStr)-2]
	}
	
	return summaryStr
}

// Running-config analysis

func analyzeRunningConfig(output string) []string {
	var annotations []string
	
	// Check for key configuration sections
	if strings.Contains(output, "router ospf") {
		annotations = append(annotations, "OSPF routing is configured")
	}
	
	if strings.Contains(output, "router eigrp") {
		annotations = append(annotations, "EIGRP routing is configured")
	}
	
	if strings.Contains(output, "router bgp") {
		annotations = append(annotations, "BGP routing is configured")
	}
	
	if strings.Contains(output, "ip route") {
		annotations = append(annotations, "Static routes are configured")
	}
	
	if strings.Contains(output, "access-list") || strings.Contains(output, "ip access-list") {
		annotations = append(annotations, "Access lists are configured")
	}
	
	if strings.Contains(output, "vlan") {
		annotations = append(annotations, "VLANs are configured")
	}
	
	if strings.Contains(output, "interface Vlan") {
		annotations = append(annotations, "VLAN interfaces are configured")
	}
	
	if strings.Contains(output, "spanning-tree") {
		annotations = append(annotations, "Spanning Tree Protocol is configured")
	}
	
	return annotations
}

// extractLastLogs extracts the last n log entries from the command output
func extractLastLogs(output string, n int) []string {
	// Split the output into lines
	lines := strings.Split(output, "\n")
	
	// Filter out empty lines and headers
	var logEntries []string
	logStarted := false
	
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		
		// Skip empty lines
		if trimmedLine == "" {
			continue
		}
		
		// Check if this line looks like a log entry
		// Most log entries start with a timestamp or sequence number
		isLogEntry := regexp.MustCompile(`^\*|^\d+|^\w{3}\s+\d+|^\d{2}:\d{2}:\d{2}`).MatchString(trimmedLine)
		
		if isLogEntry {
			logStarted = true
			logEntries = append(logEntries, trimmedLine)
		} else if logStarted && !strings.HasPrefix(trimmedLine, "Log") && 
			!strings.HasPrefix(trimmedLine, "Total") && 
			!strings.HasPrefix(trimmedLine, "--") {
			// Continue capturing lines that are part of a log entry but don't match the pattern
			// This handles multi-line log entries
			// Skip lines that look like headers or footers
			logEntries = append(logEntries, trimmedLine)
		}
	}
	
	// Get the last n entries, or all if there are fewer than n
	if len(logEntries) <= n {
		return logEntries
	}
	return logEntries[len(logEntries)-n:]
}