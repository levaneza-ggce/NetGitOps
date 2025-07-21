# Go Network Configuration Automator

A Go-based tool for automating the configuration of network devices using a simple YAML file. This application securely retrieves credentials from HashiCorp Vault, connects to devices via SSH, and can either apply configurations or compare existing device configurations with the desired state defined in YAML.

## Modes of Operation

The tool supports four modes of operation:

1. **Apply Mode**: Applies the configuration defined in the YAML file to the network devices and runs verification commands.
2. **Compare Mode**: Retrieves the current configuration from network devices and compares it with the desired state defined in the YAML file, reporting any differences.
3. **Watch Mode**: Monitors the YAML configuration file for changes and automatically applies those changes to the network devices when the file is modified. This implements a declarative approach to network configuration management.
4. **Logs Mode**: Retrieves and displays the last 15 log entries from each network device defined in the configuration file.

## Declarative Configuration Management

This tool implements a declarative approach to network configuration management, particularly through the watch mode. In a declarative approach, you define the desired state of your network in the YAML file, and the tool ensures that the actual state of the network matches this desired state.

### Benefits of the Declarative Approach:

- **Simplicity**: Define what you want, not how to achieve it
- **Consistency**: Ensure that all devices are configured according to the desired state
- **Version Control**: Store your network configuration in version control systems
- **Automation**: Automatically apply changes when the desired state changes
- **Collaboration**: Multiple team members can work on the same configuration

For more details on the declarative approach and how to use it effectively, see the [Declarative Network Configuration Management](DECLARATIVE_APPROACH.md) documentation.

To see a demonstration of the declarative workflow, run the `demo_declarative_workflow.sh` script:

```bash
chmod +x demo_declarative_workflow.sh
./demo_declarative_workflow.sh
```

## Features

This tool supports a wide range of common network configuration tasks, all defined in a single YAML file.

#### Core Features
- **Declarative Configuration**: Define your device's entire desired state in `config.yaml`.
- **Secure Credential Management**: Integrates with HashiCorp Vault to keep device credentials safe. The application reads credential paths from the config file and fetches the secrets at runtime.
- **Configure then Verify**: Applies the entire configuration first, then runs a list of `show` commands to verify the final state.

---

#### Layer 2 Features
- **VLANs**:
  - Create VLANs with a specific ID.
  - Assign an optional descriptive name to each VLAN.
- **Port-Channels (EtherChannel)**:
  - Create logical Port-Channel interfaces.
  - Set descriptions and switchport modes (e.g., `trunk`).
  - Define a list of allowed VLANs for trunk ports.
- **Interface Configuration**:
  - Configure any physical interface (e.g., `GigabitEthernet0/1`).
  - Set descriptions, and administratively enable/disable ports (`shutdown: false/true`).
  - Configure switchport modes (`access` or `trunk`).
  - Assign an interface to an access VLAN.
  - Assign a physical interface to a Port-Channel using a specific `mode` (e.g., `active` for LACP).

---

#### Layer 3 Features
- **Static Routes**:
  - Configure static IP routes with a destination prefix, mask, and next-hop address.
  - Set an optional `admin_distance` to influence route preference.
- **EIGRP (Enhanced Interior Gateway Routing Protocol)**:
  - Enable an EIGRP process with a specific `as_number`.
  - Set a unique `router_id`.
  - Advertise networks into the EIGRP domain.
  - Specify `passive_interfaces` to prevent sending EIGRP hellos.
- **OSPF (Open Shortest Path First)**:
  - Enable an OSPF process with a `process_id`.
  - Set a unique `router_id`.
  - Originate a default route into the OSPF domain (`default_information_originate`).
  - Adjust the `auto_cost_reference_bandwidth` for high-speed links.
  - Specify `passive_interfaces`.
  - Advertise specific `networks` into a given OSPF `area`.
  - Configure area-specific settings, such as `authentication: "message-digest"` for MD5.

## Setup

1.  **Clone the Repository**: `git clone <your-repo-url>`
2.  **Configure Vault**: Store device credentials in Vault (e.g., at `kv/data/network-devices/router1`).
3.  **Set Environment Variables**: The application requires `VAULT_ADDR` and `VAULT_TOKEN` to be set in your shell to authenticate with Vault.
4.  **Create `config.yaml`**: Create the configuration file in the project root. See the complete example below.
5.  **Build the Application**: Build the Go application.
    ```bash
    go build -o devnetops
    ```

## Usage

The application supports two modes of operation: `apply` and `compare`. You can specify the mode using the `-mode` flag.

### Apply Mode

Apply mode is used to configure network devices according to the YAML file.

```bash
./devnetops -mode=apply -config=config.yaml
```

### Compare Mode

Compare mode retrieves the current configuration from network devices and compares it with the desired state defined in the YAML file.

```bash
./devnetops -mode=compare -config=config.yaml
```

### Watch Mode

Watch mode monitors the YAML configuration file for changes and automatically applies those changes to the network devices when the file is modified. This is useful for continuous configuration management.

```bash
./devnetops -mode=watch -config=config.yaml -debounce=200ms
```

The watch mode will:
1. Monitor the specified configuration file for changes
2. When changes are detected, wait for the debounce interval to ensure no more rapid changes are occurring
3. Load the updated configuration
4. Apply the changes to all devices defined in the configuration

To stop the watch mode, press Ctrl+C.

### Logs Mode

Logs mode retrieves and displays the last 15 log entries from each network device defined in the configuration file. This is useful for quickly checking the recent activity on your devices without having to manually connect to each one.

```bash
./devnetops -mode=logs -config=config.yaml
```

The logs mode will:
1. Connect to each device defined in the configuration file
2. Execute the "show logging" command
3. Extract and display the last 15 log entries
4. Format the output for easy reading
5. Save the logs to a file named `device_logs_{hostname}_{timestamp}.txt` for future reference

### Command-line Flags

- `-mode`: Operation mode (`apply`, `compare`, `watch`, or `logs`). Default is `apply`.
- `-config`: Path to the configuration file. Default is `config.yaml`.
- `-debounce`: Debounce interval for watch mode (e.g., 200ms, 1s). Default is 200ms. This prevents multiple rapid changes from triggering multiple configuration applications.

## Full Configuration Example (`config.yaml`)

This `config.yaml` file demonstrates every supported feature.

```yaml
# ------------------
# Vault & Verification
# ------------------
# A list of paths in Vault where device credentials are stored.
device_secrets:
  - path: "kv/data/network-devices/router1"

# A list of commands to run AFTER the configuration is applied.
verify_commands:
  - "show ip interface brief"
  - "show vlan brief"
  - "show etherchannel summary"
  - "show ip route"
  - "show ip ospf neighbor"
  - "show ip eigrp neighbors"

# ------------------
# Layer 2 Configuration
# ------------------
vlans:
  - id: 10
    name: USERS
  - id: 20
    name: SERVERS
  - id: 30
    name: VOICE
  - id: 99
    name: MANAGEMENT

port_channels:
  - id: 1
    description: "Trunk-to-Core-SW2"
    switchport_mode: "trunk"
    trunk_allowed_vlans: "10,20,30,99"
  - id: 2
    description: "Trunk-to-Access-SW1"
    switchport_mode: "trunk"
    trunk_allowed_vlans: "10,30"

interfaces:
  # Interface assigned to a Port-Channel
  - name: "GigabitEthernet0/0"
    description: "Link-1-to-Core-SW2"
    shutdown: false
    channel_group:
      id: 1
      mode: "active" # LACP

  # Standard access port
  - name: "GigabitEthernet0/1"
    description: "PC-Port-User-Desktop"
    shutdown: false
    switchport_mode: "access"
    access_vlan: 10

  # A disabled/shutdown port
  - name: "GigabitEthernet0/2"
    description: "SPARE_PORT"
    shutdown: true

# ------------------
# Layer 3 Routing
# ------------------
static_routes:
  - prefix: "172.16.1.0"
    mask: "255.255.255.0"
    next_hop: "10.1.1.2"
  - prefix: "0.0.0.0" # Default Route
    mask: "0.0.0.0"
    next_hop: "10.1.1.2"
    admin_distance: 250 # Floating static

ospf:
  process_id: 100
  router_id: "10.0.0.1"
  default_information_originate: true
  auto_cost_reference_bandwidth: 1000
  passive_interfaces:
    - "GigabitEthernet0/1"
  networks:
    - network: "10.1.1.0"
      wildcard_mask: "0.0.0.255"
      area: "0"
    - network: "192.168.2.0"
      wildcard_mask: "0.0.0.255"
      area: "0"
  areas:
    - area_id: "0"
      authentication: "message-digest"

eigrp:
  as_number: 90
  router_id: "10.0.0.90"
  passive_interfaces:
    - "GigabitEthernet0/1"
  networks:
    - network: "192.168.90.0"
      wildcard_mask: "0.0.0.255"
    - network: "10.0.90.0" # Assumes classful mask