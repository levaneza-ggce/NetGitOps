package main

import (
	"fmt"
)

// GenerateCommands creates a list of CLI commands from the configuration struct.
func GenerateCommands(cfg *Config) []string {
	var commands []string

	// VLANs
	for _, vlan := range cfg.VLANs {
		commands = append(commands, fmt.Sprintf("vlan %d", vlan.ID))
		if vlan.Name != "" {
			commands = append(commands, fmt.Sprintf("name %s", vlan.Name))
		}
	}

	// Interfaces
	for _, iface := range cfg.Interfaces {
		commands = append(commands, fmt.Sprintf("interface %s", iface.Name))
		if iface.Description != "" {
			commands = append(commands, fmt.Sprintf("description %s", iface.Description))
		}
		if iface.IPAddress != "" && iface.SubnetMask != "" {
			commands = append(commands, fmt.Sprintf("ip address %s %s", iface.IPAddress, iface.SubnetMask))
		}
		if iface.Shutdown {
			commands = append(commands, "shutdown")
		} else {
			commands = append(commands, "no shutdown")
		}
	}

 // OSPF
	if cfg.OSPF.ProcessID != 0 {
		commands = append(commands, fmt.Sprintf("router ospf %d", cfg.OSPF.ProcessID))
		if cfg.OSPF.RouterID != "" {
			commands = append(commands, fmt.Sprintf("router-id %s", cfg.OSPF.RouterID))
		}
		
		// Handle auto-cost reference-bandwidth
		if cfg.OSPF.ReferenceBandwidth != 0 {
			commands = append(commands, fmt.Sprintf("auto-cost reference-bandwidth %d", cfg.OSPF.ReferenceBandwidth))
		}
		
		// Updated loop to handle the OSPFNetwork struct with a string Area
		for _, network := range cfg.OSPF.Networks {
			commands = append(commands, fmt.Sprintf("network %s %s area %s", network.Address, network.Wildcard, network.Area))
		}
		
		// Handle passive interfaces
		for _, intf := range cfg.OSPF.PassiveInterfaces {
			commands = append(commands, fmt.Sprintf("passive-interface %s", intf))
		}
		
		// Handle area authentication
		for _, area := range cfg.OSPF.Areas {
			if area.Authentication != "" {
				commands = append(commands, fmt.Sprintf("area %s authentication %s", area.AreaID, area.Authentication))
			}
		}
		
		// Handle default-information originate
		if cfg.OSPF.DefaultInformationOriginate {
			commands = append(commands, "default-information originate")
		} else {
			commands = append(commands, "no default-information originate")
		}
	}

	// EIGRP
	if cfg.EIGRP.ASNumber != 0 {
		commands = append(commands, fmt.Sprintf("router eigrp %d", cfg.EIGRP.ASNumber))
		
		// Handle router-id if specified
		if cfg.EIGRP.RouterID != "" {
			commands = append(commands, fmt.Sprintf("eigrp router-id %s", cfg.EIGRP.RouterID))
		}
		
		// Handle networks
		for _, network := range cfg.EIGRP.Networks {
			commands = append(commands, fmt.Sprintf("network %s", network))
		}
		
		// Handle passive interfaces
		for _, intf := range cfg.EIGRP.PassiveInterfaces {
			commands = append(commands, fmt.Sprintf("passive-interface %s", intf))
		}
	}

	// Static Routes
	for _, route := range cfg.StaticRoutes {
		nextHopStr := ""
		// Handle simple string next-hop or complex map
		switch v := route.NextHop.(type) {
		case string:
			nextHopStr = v
		case map[string]interface{}:
			// Assuming the map has an 'ip_address' key for now
			if ip, ok := v["ip_address"]; ok {
				nextHopStr = fmt.Sprintf("%v", ip)
			}
		}
		if nextHopStr != "" {
			commands = append(commands, fmt.Sprintf("ip route %s %s %s", route.Network, route.SubnetMask, nextHopStr))
		}
	}

	// Route Maps
	for _, rm := range cfg.RouteMaps {
		for _, clause := range rm.Clauses {
			commands = append(commands, fmt.Sprintf("route-map %s %s %d", rm.Name, clause.Action, clause.Sequence))
			if clause.Description != "" {
				commands = append(commands, fmt.Sprintf("description %s", clause.Description))
			}
			// Example of processing a 'set' clause
			if setClause, ok := clause.Set.(map[string]interface{}); ok {
				if metric, exists := setClause["metric"]; exists {
					commands = append(commands, fmt.Sprintf("set metric %v", metric))
				}
			}
			// Example of processing a 'match' clause
			if matchClause, ok := clause.Match.(map[string]interface{}); ok {
				if ip, exists := matchClause["ip_address"]; exists {
					if prefixList, ok := ip.(map[string]interface{})["prefix-list"]; ok {
						commands = append(commands, fmt.Sprintf("match ip address prefix-list %v", prefixList))
					}
				}
			}
		}
	}

	return commands
}

// ExecuteConfiguration connects to a device and applies the provided configuration commands.
func ExecuteConfiguration(creds *VaultCredentials, commands []string) error {
	client, err := NewRealSSHClient(creds.Host, creds.Username, creds.Password)
	if err != nil {
		return fmt.Errorf("failed to connect to %s: %w", creds.Host, err)
	}
	defer client.Close()

	// Prepare the full sequence of commands, including entering and exiting configuration mode.
	fullCommandSequence := []string{
		"enable",
		creds.EnableSecret,
		"configure terminal",
	}
	fullCommandSequence = append(fullCommandSequence, commands...)
	// Exit config mode, save, and explicitly exit the session to prevent hanging
	fullCommandSequence = append(fullCommandSequence, "end", "write memory", "exit")

	_, err = client.Run(fullCommandSequence...)
	if err != nil {
		return fmt.Errorf("failed during command execution on %s: %w", creds.Host, err)
	}

	return nil
}