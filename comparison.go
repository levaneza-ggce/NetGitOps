package main

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
)

// DeviceConfig represents the actual configuration retrieved from a device
type DeviceConfig struct {
	VLANs        map[int]VLAN
	Interfaces   map[string]Interface
	OSPF         OSPF
	EIGRP        EIGRP
	StaticRoutes []StaticRoute
}

// RetrieveDeviceConfig connects to a device and retrieves its current configuration
func RetrieveDeviceConfig(creds *VaultCredentials) (*DeviceConfig, error) {
	client, err := NewRealSSHClient(creds.Host, creds.Username, creds.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", creds.Host, err)
	}
	defer client.Close()

	// Commands to retrieve different parts of the configuration
	commands := []string{
		"enable",
		creds.EnableSecret,
		"terminal length 0",
		"show running-config",
		"show vlan brief",
		"show ip interface brief",
		"show ip route static",
		"show ip ospf",
		"show ip eigrp",
		"show running-config | section router ospf",
		"exit",
	}

	output, err := client.Run(commands...)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve configuration from %s: %w", creds.Host, err)
	}

	// Parse the output into a structured format
	config := &DeviceConfig{
		VLANs:        make(map[int]VLAN),
		Interfaces:   make(map[string]Interface),
		StaticRoutes: []StaticRoute{},
	}

	// Clean the output and parse it
	cleanedOutput := cleanShellOutput(output)
	parseRunningConfig(cleanedOutput, config)
	parseVLANs(cleanedOutput, config)
	parseInterfaces(cleanedOutput, config)
	parseStaticRoutes(cleanedOutput, config)
	parseOSPF(cleanedOutput, config)
	parseEIGRP(cleanedOutput, config)

	return config, nil
}

// parseRunningConfig parses the full running configuration
func parseRunningConfig(output string, config *DeviceConfig) {
	// This is a simplified implementation
	// In a real implementation, you would parse the entire running config
	// and extract all the relevant configuration sections
}

// parseVLANs parses the output of "show vlan brief"
func parseVLANs(output string, config *DeviceConfig) {
	// Example regex for parsing VLAN output
	vlanRegex := regexp.MustCompile(`(\d+)\s+(\S+)\s+`)
	
	// Find all matches in the output
	for _, line := range strings.Split(output, "\n") {
		matches := vlanRegex.FindStringSubmatch(line)
		if len(matches) >= 3 {
			id, _ := strconv.Atoi(matches[1])
			config.VLANs[id] = VLAN{
				ID:   id,
				Name: matches[2],
			}
		}
	}
}

// parseInterfaces parses the output of "show ip interface brief"
func parseInterfaces(output string, config *DeviceConfig) {
	// Example regex for parsing interface output
	ifaceRegex := regexp.MustCompile(`(\S+)\s+(\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(\S+)`)
	
	// Find all matches in the output
	for _, line := range strings.Split(output, "\n") {
		matches := ifaceRegex.FindStringSubmatch(line)
		if len(matches) >= 4 {
			name := matches[1]
			ipAddress := matches[2]
			status := matches[3]
			
			config.Interfaces[name] = Interface{
				Name:       name,
				IPAddress:  ipAddress,
				Shutdown:   status != "up",
			}
		}
	}
}

// parseStaticRoutes parses the output of "show ip route static"
func parseStaticRoutes(output string, config *DeviceConfig) {
	// Example regex for parsing static routes
	routeRegex := regexp.MustCompile(`S\s+(\d+\.\d+\.\d+\.\d+)/(\d+)\s+\[(\d+)/\d+\]\s+via\s+(\d+\.\d+\.\d+\.\d+)`)
	
	// Find all matches in the output
	for _, line := range strings.Split(output, "\n") {
		matches := routeRegex.FindStringSubmatch(line)
		if len(matches) >= 5 {
			prefix := matches[1]
			mask, _ := strconv.Atoi(matches[2])
			ad, _ := strconv.Atoi(matches[3])
			nextHop := matches[4]
			
			// Convert CIDR mask to subnet mask
			subnetMask := cidrToSubnetMask(mask)
			
			config.StaticRoutes = append(config.StaticRoutes, StaticRoute{
				Network:    prefix,
				SubnetMask: subnetMask,
				NextHop:    nextHop,
				AdminAD:    ad,
			})
		}
	}
}

// parseOSPF parses the output of "show ip ospf" and "show running-config | section router ospf"
func parseOSPF(output string, config *DeviceConfig) {
	// Initialize OSPF struct
	config.OSPF = OSPF{}
	
	// Parse OSPF process ID and router ID
	// First try from "show ip ospf" output
	processRegex := regexp.MustCompile(`Routing Process "ospf (\d+)" with ID (\d+\.\d+\.\d+\.\d+)`)
	matches := processRegex.FindStringSubmatch(output)
	if len(matches) >= 3 {
		processID, _ := strconv.Atoi(matches[1])
		routerID := matches[2]
		
		config.OSPF.ProcessID = processID
		config.OSPF.RouterID = routerID
	} else {
		// Try from "show running-config | section router ospf" output
		routerOspfRegex := regexp.MustCompile(`router ospf (\d+)`)
		routerIdRegex := regexp.MustCompile(`router-id (\d+\.\d+\.\d+\.\d+)`)
		
		routerOspfMatches := routerOspfRegex.FindStringSubmatch(output)
		if len(routerOspfMatches) >= 2 {
			processID, _ := strconv.Atoi(routerOspfMatches[1])
			config.OSPF.ProcessID = processID
		}
		
		routerIdMatches := routerIdRegex.FindStringSubmatch(output)
		if len(routerIdMatches) >= 2 {
			config.OSPF.RouterID = routerIdMatches[1]
		}
	}
	
	// Parse auto-cost reference-bandwidth
	autoCostRegex := regexp.MustCompile(`auto-cost reference-bandwidth (\d+)`)
	autoCostMatches := autoCostRegex.FindStringSubmatch(output)
	if len(autoCostMatches) >= 2 {
		autoCostRefBw, _ := strconv.Atoi(autoCostMatches[1])
		config.OSPF.ReferenceBandwidth = autoCostRefBw
	}
	
	// Parse default-information originate
	// Check both formats: "Default Information Originate" and "default-information originate"
	defaultInfoRegex1 := regexp.MustCompile(`Default Information Originate`)
	defaultInfoRegex2 := regexp.MustCompile(`default-information originate`)
	if defaultInfoRegex1.MatchString(output) || defaultInfoRegex2.MatchString(output) {
		config.OSPF.DefaultInformationOriginate = true
	}
	
	// Parse areas and their authentication
	// Check both formats: "Area 0 authentication message-digest" and "area 0 authentication message-digest"
	areaRegex1 := regexp.MustCompile(`Area (\d+) authentication (message-digest|simple)`)
	areaRegex2 := regexp.MustCompile(`area (\d+) authentication (message-digest|simple)`)
	
	areaMatches1 := areaRegex1.FindAllStringSubmatch(output, -1)
	for _, match := range areaMatches1 {
		if len(match) >= 3 {
			areaID := match[1]
			authType := match[2]
			config.OSPF.Areas = append(config.OSPF.Areas, OSPFArea{
				AreaID:        areaID,
				Authentication: authType,
			})
		}
	}
	
	areaMatches2 := areaRegex2.FindAllStringSubmatch(output, -1)
	for _, match := range areaMatches2 {
		if len(match) >= 3 {
			areaID := match[1]
			authType := match[2]
			config.OSPF.Areas = append(config.OSPF.Areas, OSPFArea{
				AreaID:        areaID,
				Authentication: authType,
			})
		}
	}
	
	// Parse passive interfaces
	// Use a map to track unique passive interfaces
	passiveInterfacesMap := make(map[string]bool)
	
	// Check both formats: "Passive Interface(s): ..." and "passive-interface ..."
	passiveRegex1 := regexp.MustCompile(`Passive Interface\(s\):\s+(.+)`)
	passiveMatches1 := passiveRegex1.FindStringSubmatch(output)
	if len(passiveMatches1) >= 2 {
		passiveInterfaces := strings.Split(passiveMatches1[1], ", ")
		for _, iface := range passiveInterfaces {
			passiveInterfacesMap[iface] = true
		}
	}
	
	passiveRegex2 := regexp.MustCompile(`passive-interface (\S+)`)
	passiveMatches2 := passiveRegex2.FindAllStringSubmatch(output, -1)
	for _, match := range passiveMatches2 {
		if len(match) >= 2 {
			passiveInterfacesMap[match[1]] = true
		}
	}
	
	// Convert the map keys to a slice
	for iface := range passiveInterfacesMap {
		config.OSPF.PassiveInterfaces = append(config.OSPF.PassiveInterfaces, iface)
	}
	
	// Parse OSPF networks from "show running-config | section router ospf" output
	networkRegex := regexp.MustCompile(`network\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+\.\d+\.\d+)\s+area\s+(\d+)`)
	networkMatches := networkRegex.FindAllStringSubmatch(output, -1)
	for _, match := range networkMatches {
		if len(match) >= 4 {
			network := match[1]
			wildcardMask := match[2]
			area := match[3]
			config.OSPF.Networks = append(config.OSPF.Networks, OSPFNetwork{
				Address:  network,
				Wildcard: wildcardMask,
				Area:     area,
			})
		}
	}
}

// parseEIGRP parses the output of "show ip eigrp"
func parseEIGRP(output string, config *DeviceConfig) {
	// Example regex for parsing EIGRP AS number
	asRegex := regexp.MustCompile(`EIGRP-IPv4 Protocol with AS (\d+)`)
	
	// Find the AS number
	matches := asRegex.FindStringSubmatch(output)
	if len(matches) >= 2 {
		asNumber, _ := strconv.Atoi(matches[1])
		
		// Initialize EIGRP struct with AS number
		config.EIGRP = EIGRP{
			ASNumber: asNumber,
		}
		
		// Parse router ID
		routerIDRegex := regexp.MustCompile(`Router ID: (\d+\.\d+\.\d+\.\d+)`)
		routerIDMatches := routerIDRegex.FindStringSubmatch(output)
		if len(routerIDMatches) >= 2 {
			config.EIGRP.RouterID = routerIDMatches[1]
		}
		
		// Parse passive interfaces
		passiveRegex := regexp.MustCompile(`Passive Interface\(s\):\s+(.+)`)
		passiveMatches := passiveRegex.FindStringSubmatch(output)
		if len(passiveMatches) >= 2 {
			passiveInterfaces := strings.Split(passiveMatches[1], ", ")
			config.EIGRP.PassiveInterfaces = passiveInterfaces
		}
		
		// Parse networks
		networkRegex := regexp.MustCompile(`Network\(s\):\s+(.+)`)
		networkMatches := networkRegex.FindStringSubmatch(output)
		if len(networkMatches) >= 2 {
			networks := strings.Split(networkMatches[1], ", ")
			config.EIGRP.Networks = networks
		}
	}
}

// cidrToSubnetMask converts a CIDR prefix length to a subnet mask
func cidrToSubnetMask(cidr int) string {
	// Convert CIDR to subnet mask
	var mask uint32 = 0xffffffff
	mask = mask << (32 - cidr)
	
	// Convert to dotted decimal notation
	return fmt.Sprintf("%d.%d.%d.%d",
		(mask>>24)&0xff,
		(mask>>16)&0xff,
		(mask>>8)&0xff,
		mask&0xff,
	)
}

// CompareConfigurations compares the desired configuration with the actual device configuration
func CompareConfigurations(desired *Config, actual *DeviceConfig) []string {
	var differences []string
	
	// Compare VLANs
	for _, desiredVLAN := range desired.VLANs {
		actualVLAN, exists := actual.VLANs[desiredVLAN.ID]
		if !exists {
			differences = append(differences, fmt.Sprintf("VLAN %d is missing on the device", desiredVLAN.ID))
		} else if actualVLAN.Name != desiredVLAN.Name {
			differences = append(differences, fmt.Sprintf("VLAN %d name mismatch: desired '%s', actual '%s'", 
				desiredVLAN.ID, desiredVLAN.Name, actualVLAN.Name))
		}
	}
	
	// Compare Interfaces
	for _, desiredIface := range desired.Interfaces {
		actualIface, exists := actual.Interfaces[desiredIface.Name]
		if !exists {
			differences = append(differences, fmt.Sprintf("Interface %s is missing on the device", desiredIface.Name))
			continue
		}
		
		if desiredIface.Description != "" && actualIface.Description != desiredIface.Description {
			differences = append(differences, fmt.Sprintf("Interface %s description mismatch: desired '%s', actual '%s'", 
				desiredIface.Name, desiredIface.Description, actualIface.Description))
		}
		
		if desiredIface.IPAddress != "" && actualIface.IPAddress != desiredIface.IPAddress {
			differences = append(differences, fmt.Sprintf("Interface %s IP address mismatch: desired '%s', actual '%s'", 
				desiredIface.Name, desiredIface.IPAddress, actualIface.IPAddress))
		}
		
		if desiredIface.Shutdown != actualIface.Shutdown {
			if desiredIface.Shutdown {
				differences = append(differences, fmt.Sprintf("Interface %s should be shutdown but is up", desiredIface.Name))
			} else {
				differences = append(differences, fmt.Sprintf("Interface %s should be up but is shutdown", desiredIface.Name))
			}
		}
	}
	
	// Compare OSPF
	if desired.OSPF.ProcessID != 0 {
		if actual.OSPF.ProcessID != desired.OSPF.ProcessID {
			differences = append(differences, fmt.Sprintf("OSPF process ID mismatch: desired %d, actual %d", 
				desired.OSPF.ProcessID, actual.OSPF.ProcessID))
		}
		
		if desired.OSPF.RouterID != "" && actual.OSPF.RouterID != desired.OSPF.RouterID {
			differences = append(differences, fmt.Sprintf("OSPF router ID mismatch: desired '%s', actual '%s'", 
				desired.OSPF.RouterID, actual.OSPF.RouterID))
		}
		
		// Compare auto-cost reference-bandwidth
		if desired.OSPF.ReferenceBandwidth != 0 && desired.OSPF.ReferenceBandwidth != actual.OSPF.ReferenceBandwidth {
			differences = append(differences, fmt.Sprintf("OSPF auto-cost reference-bandwidth mismatch: desired %d, actual %d", 
				desired.OSPF.ReferenceBandwidth, actual.OSPF.ReferenceBandwidth))
		}
		
		// Compare default-information originate
		if desired.OSPF.DefaultInformationOriginate != actual.OSPF.DefaultInformationOriginate {
			differences = append(differences, fmt.Sprintf("OSPF default-information originate mismatch: desired %v, actual %v", 
				desired.OSPF.DefaultInformationOriginate, actual.OSPF.DefaultInformationOriginate))
		}
		
		// Compare passive interfaces
		// First, check if desired passive interfaces are present on the device
		for _, desiredInterface := range desired.OSPF.PassiveInterfaces {
			found := false
			for _, actualInterface := range actual.OSPF.PassiveInterfaces {
				if desiredInterface == actualInterface {
					found = true
					break
				}
			}
			if !found {
				differences = append(differences, fmt.Sprintf("OSPF passive interface missing: %s", desiredInterface))
			}
		}
		
		// Then, check if there are additional passive interfaces on the device not defined in YAML
		for _, actualInterface := range actual.OSPF.PassiveInterfaces {
			found := false
			for _, desiredInterface := range desired.OSPF.PassiveInterfaces {
				if actualInterface == desiredInterface {
					found = true
					break
				}
			}
			if !found {
				differences = append(differences, fmt.Sprintf("OSPF has unexpected passive interface: %s", actualInterface))
			}
		}
		
		// Compare networks
		for _, desiredNetwork := range desired.OSPF.Networks {
			found := false
			for _, actualNetwork := range actual.OSPF.Networks {
				if desiredNetwork.Address == actualNetwork.Address && 
				   desiredNetwork.Wildcard == actualNetwork.Wildcard && 
				   desiredNetwork.Area == actualNetwork.Area {
					found = true
					break
				}
			}
			if !found {
				differences = append(differences, fmt.Sprintf("OSPF network missing: %s %s area %s", 
					desiredNetwork.Address, desiredNetwork.Wildcard, desiredNetwork.Area))
			}
		}
		
		// Compare areas
		for _, desiredArea := range desired.OSPF.Areas {
			found := false
			for _, actualArea := range actual.OSPF.Areas {
				if desiredArea.AreaID == actualArea.AreaID {
					if desiredArea.Authentication != actualArea.Authentication {
						differences = append(differences, fmt.Sprintf("OSPF area %s authentication mismatch: desired '%s', actual '%s'", 
							desiredArea.AreaID, desiredArea.Authentication, actualArea.Authentication))
					}
					found = true
					break
				}
			}
			if !found {
				differences = append(differences, fmt.Sprintf("OSPF area missing: %s", desiredArea.AreaID))
			}
		}
	}
	
	// Compare EIGRP
	if desired.EIGRP.ASNumber != 0 {
		if actual.EIGRP.ASNumber != desired.EIGRP.ASNumber {
			differences = append(differences, fmt.Sprintf("EIGRP AS number mismatch: desired %d, actual %d", 
				desired.EIGRP.ASNumber, actual.EIGRP.ASNumber))
		}
		
		// Compare router ID
		if desired.EIGRP.RouterID != "" && actual.EIGRP.RouterID != desired.EIGRP.RouterID {
			differences = append(differences, fmt.Sprintf("EIGRP router ID mismatch: desired '%s', actual '%s'", 
				desired.EIGRP.RouterID, actual.EIGRP.RouterID))
		}
		
		// Compare passive interfaces
		for _, desiredInterface := range desired.EIGRP.PassiveInterfaces {
			found := false
			for _, actualInterface := range actual.EIGRP.PassiveInterfaces {
				if desiredInterface == actualInterface {
					found = true
					break
				}
			}
			if !found {
				differences = append(differences, fmt.Sprintf("EIGRP passive interface missing: %s", desiredInterface))
			}
		}
		
		// Compare networks
		for _, desiredNetwork := range desired.EIGRP.Networks {
			found := false
			for _, actualNetwork := range actual.EIGRP.Networks {
				if desiredNetwork == actualNetwork {
					found = true
					break
				}
			}
			if !found {
				differences = append(differences, fmt.Sprintf("EIGRP network missing: %s", desiredNetwork))
			}
		}
	}
	
	return differences
}

// PrintComparisonResults prints the comparison results in a user-friendly format
func PrintComparisonResults(differences []string) {
	if len(differences) == 0 {
		log.Println("✅ Device configuration matches the desired state")
		return
	}
	
	log.Println("❌ Device configuration does not match the desired state")
	log.Println("Differences found:")
	for i, diff := range differences {
		log.Printf("  %d. %s", i+1, diff)
	}
}