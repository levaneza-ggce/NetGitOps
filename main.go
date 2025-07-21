package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHClient defines the interface for an SSH client.
type SSHClient interface {
	Run(command ...string) (string, error)
	Close() error
}

// RealSSHClient is the concrete implementation of SSHClient.
type RealSSHClient struct {
	Client *ssh.Client
}

// NewRealSSHClient creates and connects a new SSH client.
func NewRealSSHClient(host, username, password string) (*RealSSHClient, error) {
	sshConfig := ssh.Config{
		KeyExchanges: []string{
			"diffie-hellman-group-exchange-sha256", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1",
		},
		Ciphers: []string{
			"aes256-ctr", "aes192-ctr", "aes128-ctr", "aes256-cbc", "aes192-cbc", "aes128-cbc",
		},
	}
	config := &ssh.ClientConfig{
		User:            username,
		Auth:            []ssh.AuthMethod{ssh.Password(password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
		Config:          sshConfig,
	}

	if !strings.Contains(host, ":") {
		host = host + ":22"
	}
	client, err := ssh.Dial("tcp", host, config)
	if err != nil {
		return nil, err
	}
	return &RealSSHClient{Client: client}, nil
}

// Run executes a sequence of commands on the remote SSH server in an interactive shell.
func (c *RealSSHClient) Run(commands ...string) (string, error) {
	session, err := c.Client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()

	stdin, err := session.StdinPipe()
	if err != nil {
		return "", err
	}
	var stdoutBuf bytes.Buffer
	session.Stdout = &stdoutBuf

	if err := session.Shell(); err != nil {
		return "", err
	}

	for _, cmd := range commands {
		if _, err := stdin.Write([]byte(cmd + "\n")); err != nil {
			return stdoutBuf.String(), fmt.Errorf("failed to write command '%s': %w", cmd, err)
		}
	}

	// Create a channel to signal when session.Wait() completes
	done := make(chan error, 1)
	go func() {
		done <- session.Wait()
	}()

	// Wait for session.Wait() to complete or timeout after 60 seconds
	select {
	case err := <-done:
		if err != nil {
			if _, ok := err.(*ssh.ExitMissingError); !ok && err.Error() != "Process exited with status 1" {
				return stdoutBuf.String(), err
			}
		}
	case <-time.After(30 * time.Second):
		return stdoutBuf.String(), fmt.Errorf("command execution timed out after 30 seconds")
	}

	return stdoutBuf.String(), nil
}

// Close closes the SSH client connection.
func (c *RealSSHClient) Close() error {
	return c.Client.Close()
}

// RunVerificationCheck connects, runs commands, and logs the cleaned output.
func RunVerificationCheck(creds *VaultCredentials, title string, commands ...string) {
	log.Println(title)
	client, err := NewRealSSHClient(creds.Host, creds.Username, creds.Password)
	if err != nil {
		log.Printf("  ❌ ERROR: Failed to connect to %s: %v", creds.Host, err)
		return
	}
	defer client.Close()

	output, err := client.Run(commands...)
	if err != nil {
		log.Printf("  ❌ ERROR: Command execution failed: %v", err)
	}

	// Clean the raw output to remove shell prompts and echoed commands.
	cleanedOutput := cleanShellOutput(output)
	if cleanedOutput != "" {
		log.Println(cleanedOutput)
	}
}

// cleanShellOutput filters out command prompts and other noise from the raw shell output.
func cleanShellOutput(output string) string {
	var cleanedLines []string
	var hostname string

	// Standardize line endings and split into lines.
	lines := strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n")

	// Try to determine the hostname from the first line containing a prompt.
	for _, line := range lines {
		if strings.Contains(line, ">") {
			hostname = strings.Split(line, ">")[0]
			break
		}
		if strings.Contains(line, "#") {
			hostname = strings.Split(line, "#")[0]
			break
		}
	}

	// Filter the output line by line.
	for _, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			continue
		}
		// If we detected a hostname, use it for more precise filtering.
		if hostname != "" {
			if strings.HasPrefix(trimmedLine, hostname+">") || strings.HasPrefix(trimmedLine, hostname+"#") || trimmedLine == "Password:" {
				continue
			}
		} else if trimmedLine == "Password:" { // Fallback if hostname detection fails
			continue
		}
		cleanedLines = append(cleanedLines, line)
	}

	return strings.TrimSpace(strings.Join(cleanedLines, "\n"))
}

func main() {
	// Define command-line flags
	modePtr := flag.String("mode", "apply", "Operation mode: 'apply' to configure devices, 'compare' to check configuration, 'watch' to monitor for changes, or 'logs' to retrieve the last 15 logs")
	configFilePtr := flag.String("config", "config.yaml", "Path to the configuration file")
	debouncePtr := flag.Duration("debounce", 200*time.Millisecond, "Debounce interval for watch mode (e.g., 200ms, 1s)")
	flag.Parse()

	// Load configuration from file
	cfg, err := LoadConfig(*configFilePtr)
	if err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	// Create Vault client
	vaultClient, err := NewVaultClient()
	if err != nil {
		log.Fatalf("❌ Failed to create vault client: %v", err)
	}

	// Execute the appropriate workflow based on the mode
	switch *modePtr {
	case "watch":
		// For watch mode, we don't process devices here
		// The WatchConfiguration function will handle loading and applying the configuration
		log.Printf("🔍 Watch mode will monitor %s for changes and apply them to all devices", *configFilePtr)
		WatchConfiguration(*configFilePtr, *debouncePtr, vaultClient)
	case "logs":
		// For logs mode, retrieve the last 15 logs from each device
		log.Printf("📜 Logs mode will retrieve the last 15 logs from each device")
		for _, secret := range cfg.DeviceSecrets {
			creds, err := GetVaultCredentials(vaultClient, secret.Path)
			if err != nil {
				log.Printf("❗ Failed to retrieve credentials from %s: %v", secret.Path, err)
				continue
			}
			log.Printf("✅ Retrieved credentials for device %s", creds.Host)
			
			// Retrieve and display the last 15 logs
			GetLastLogs(creds)
		}
	case "apply", "compare":
		// Process each device for apply and compare modes
		for _, secret := range cfg.DeviceSecrets {
			creds, err := GetVaultCredentials(vaultClient, secret.Path)
			if err != nil {
				log.Printf("❗ Failed to retrieve credentials from %s: %v", secret.Path, err)
				continue
			}
			log.Printf("✅ Retrieved credentials for device %s", creds.Host)

			// Execute the appropriate workflow based on the mode
			if *modePtr == "apply" {
				ApplyConfiguration(cfg, creds)
			} else { // compare mode
				CompareConfiguration(cfg, creds)
			}
		}
	default:
		log.Fatalf("❌ Invalid mode: %s. Use 'apply', 'compare', 'watch', or 'logs'", *modePtr)
	}
}

// ApplyConfiguration applies the configuration to the device
func ApplyConfiguration(cfg *Config, creds *VaultCredentials) {
	configCommands := GenerateCommands(cfg)

	log.Println("🚀 Applying Device Configuration...")
	if err := ExecuteConfiguration(creds, configCommands); err != nil {
		log.Fatalf("❌ Failed to apply configuration on %s: %v", creds.Host, err)
	}
	log.Println("✅ Device Configuration Applied Successfully.")
	log.Println("✅ Configuration applied. Now running verification commands.")

 // Run verification commands
	if len(cfg.VerifyCommands) > 0 {
		// Use verification commands from config with enhanced verification
		log.Println("📊 Running enhanced verification commands...")
		for _, cmd := range cfg.VerifyCommands {
			RunEnhancedVerificationCheck(creds, cmd)
		}
	} else {
		// Fallback to default verification commands with enhanced verification
		log.Println("📊 Running default enhanced verification commands...")
		RunEnhancedVerificationCheck(creds, "show ip interface brief")
		RunEnhancedVerificationCheck(creds, "show vlan brief")
		RunEnhancedVerificationCheck(creds, "show ip route")
		RunEnhancedVerificationCheck(creds, "show ip ospf neighbor")
		RunEnhancedVerificationCheck(creds, "show ip eigrp neighbors")
		RunEnhancedVerificationCheck(creds, "show running-config | include ospf")
		RunEnhancedVerificationCheck(creds, "show running-config | include eigrp")
	}
}

// CompareConfiguration compares the device's current configuration with the desired configuration
func CompareConfiguration(cfg *Config, creds *VaultCredentials) {
	log.Println("🔍 Retrieving current device configuration...")
	deviceConfig, err := RetrieveDeviceConfig(creds)
	if err != nil {
		log.Fatalf("❌ Failed to retrieve configuration from %s: %v", creds.Host, err)
	}
	log.Println("✅ Device configuration retrieved successfully.")

	log.Println("🔍 Comparing configurations...")
	differences := CompareConfigurations(cfg, deviceConfig)
	PrintComparisonResults(differences)
}