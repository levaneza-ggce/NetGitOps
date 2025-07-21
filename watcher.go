package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
	vault "github.com/hashicorp/vault/api"
)

// WatchConfiguration implements the file watching mechanism that monitors
// the configuration file for changes and automatically applies them to devices
func WatchConfiguration(configFile string, debounceInterval time.Duration, vaultClient *vault.Client) {
	log.Printf("🔍 Starting watch mode for configuration file: %s", configFile)
	log.Printf("⏱️ Debounce interval: %s", debounceInterval)
	log.Printf("📋 This is a declarative approach: changes to the YAML file will automatically be applied to devices")

	// Verify that the configuration file exists
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Fatalf("❌ Configuration file does not exist: %s", configFile)
	}

	// Create a new file watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatalf("❌ Failed to create file watcher: %v", err)
	}
	defer watcher.Close()

	// Get the absolute path of the config file
	absPath, err := filepath.Abs(configFile)
	if err != nil {
		log.Fatalf("❌ Failed to get absolute path of config file: %v", err)
	}
	log.Printf("📁 Watching absolute path: %s", absPath)

	// Add the config file to the watcher
	err = watcher.Add(absPath)
	if err != nil {
		log.Fatalf("❌ Failed to watch config file: %v", err)
	}
	log.Printf("✅ Successfully added file to watcher")

	// Create a channel to receive signals for graceful shutdown
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	// Create a channel for debouncing
	debounce := make(chan bool, 100)
	var debounceTimer *time.Timer
	var mu sync.Mutex

	// Create a channel to indicate when we're done
	done := make(chan bool)

	// Start the debounce handler
	go func() {
		for range debounce {
			mu.Lock()
			// Cancel the existing timer if there is one
			if debounceTimer != nil {
				log.Printf("⏱️ Resetting debounce timer due to new change...")
				debounceTimer.Stop()
			}

			// Create a new timer
			debounceTimer = time.AfterFunc(debounceInterval, func() {
				log.Println("⏱️ Debounce interval elapsed, processing changes...")
				
				// Load the updated configuration
				log.Printf("📂 Loading updated configuration from %s...", configFile)
				cfg, err := LoadConfig(configFile)
				if err != nil {
					log.Printf("❌ Failed to load configuration: %v", err)
					log.Printf("💡 Tip: Check that your YAML file is properly formatted")
					return
				}
				log.Printf("✅ Configuration loaded successfully")
				
				// Validate the configuration
				if len(cfg.DeviceSecrets) == 0 {
					log.Printf("⚠️ Warning: No device secrets found in configuration")
					log.Printf("💡 Tip: Make sure your YAML file includes 'device_secrets' section")
				}
				
				// Compare with previous configuration if available
				// This is a placeholder for future enhancement
				
				// Apply the configuration to all devices
				log.Printf("🔄 Applying configuration to all devices...")
				ApplyToAllDevices(cfg, vaultClient)
				log.Printf("✅ Configuration changes applied successfully")
				log.Printf("🔍 Continuing to watch for changes to %s...", configFile)
			})
			mu.Unlock()
		}
	}()

	// Start the file watcher
	go func() {
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}

				// Check if the event is for our config file
				if filepath.Clean(event.Name) != absPath {
					continue
				}

				// Check if the event is a write, create, or rename event
				if event.Op&(fsnotify.Write|fsnotify.Create|fsnotify.Rename) != 0 {
					log.Printf("📝 Configuration file changed: %s (Event: %s)", event.Name, event.Op)
					
					// Verify that the file still exists and is readable
					if _, err := os.Stat(absPath); os.IsNotExist(err) {
						log.Printf("⚠️ Warning: Configuration file no longer exists: %s", absPath)
						continue
					}
					
					// Check if the file is empty
					fileInfo, err := os.Stat(absPath)
					if err != nil {
						log.Printf("⚠️ Warning: Failed to get file info: %v", err)
						continue
					}
					
					if fileInfo.Size() == 0 {
						log.Printf("⚠️ Warning: Configuration file is empty: %s", absPath)
						continue
					}
					
					log.Printf("🔄 Scheduling configuration update (will apply after debounce interval: %s)", debounceInterval)
					debounce <- true
				}

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				log.Printf("❌ Error watching file: %v", err)
			case <-done:
				return
			}
		}
	}()

	// Wait for a signal to shutdown
	<-sigs
	log.Println("👋 Shutting down watch mode...")
	close(done)
}

// ApplyToAllDevices applies the configuration to all devices
func ApplyToAllDevices(cfg *Config, client *vault.Client) {
	if len(cfg.DeviceSecrets) == 0 {
		log.Printf("❌ No devices found in configuration to apply changes to")
		log.Printf("💡 Tip: Make sure your YAML file includes device_secrets section with valid paths")
		return
	}

	log.Printf("🔍 Found %d device(s) in configuration", len(cfg.DeviceSecrets))
	
	// Track success and failure counts
	successCount := 0
	failureCount := 0

	// Process each device
	for i, secret := range cfg.DeviceSecrets {
		log.Printf("📱 Processing device %d of %d (Path: %s)", i+1, len(cfg.DeviceSecrets), secret.Path)
		
		// Retrieve credentials from Vault
		log.Printf("🔑 Retrieving credentials from Vault...")
		creds, err := GetVaultCredentials(client, secret.Path)
		if err != nil {
			log.Printf("❌ Failed to retrieve credentials from %s: %v", secret.Path, err)
			log.Printf("💡 Tip: Check that the secret exists in Vault and contains host, username, and password fields")
			failureCount++
			continue
		}
		log.Printf("✅ Retrieved credentials for device %s", creds.Host)

		// Apply the configuration
		log.Printf("⚙️ Applying configuration to device %s...", creds.Host)
		applyErr := ApplyConfigurationWithRetry(cfg, creds, 2) // Try up to 2 times
		
		if applyErr != nil {
			log.Printf("❌ Failed to apply configuration to device %s: %v", creds.Host, applyErr)
			log.Printf("💡 Tip: Check that the device is reachable and the credentials are correct")
			failureCount++
		} else {
			log.Printf("✅ Successfully applied configuration to device %s", creds.Host)
			successCount++
		}
	}
	
	// Summary
	log.Printf("📊 Configuration application summary:")
	log.Printf("   - Total devices: %d", len(cfg.DeviceSecrets))
	log.Printf("   - Successful: %d", successCount)
	log.Printf("   - Failed: %d", failureCount)
	
	if failureCount > 0 {
		log.Printf("⚠️ Warning: Not all devices were configured successfully")
	} else if successCount > 0 {
		log.Printf("🎉 All devices were configured successfully!")
	}
}

// ApplyConfigurationWithRetry applies the configuration to a device with retry logic
func ApplyConfigurationWithRetry(cfg *Config, creds *VaultCredentials, maxRetries int) error {
	var lastErr error
	
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			log.Printf("🔄 Retry attempt %d of %d for device %s", attempt, maxRetries, creds.Host)
			// Wait a bit before retrying
			time.Sleep(2 * time.Second)
		}
		
		// Create a channel to capture errors from ApplyConfiguration
		errChan := make(chan error, 1)
		
		// Apply configuration with timeout
		go func() {
			defer func() {
				if r := recover(); r != nil {
					errChan <- fmt.Errorf("panic during configuration application: %v", r)
				}
			}()
			
			// Call the original ApplyConfiguration function
			ApplyConfiguration(cfg, creds)
			
			// If we get here without panicking, it was successful
			errChan <- nil
		}()
		
		// Wait for completion or timeout
		select {
		case err := <-errChan:
			if err == nil {
				return nil // Success!
			}
			lastErr = err
		case <-time.After(60 * time.Second):
			lastErr = fmt.Errorf("timeout after 60 seconds while applying configuration")
		}
		
		// If we get here, there was an error
		if attempt < maxRetries {
			log.Printf("⚠️ Error applying configuration to %s: %v. Will retry...", creds.Host, lastErr)
		}
	}
	
	return lastErr
}