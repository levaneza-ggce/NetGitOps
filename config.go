package main

import (
	"os"

	"gopkg.in/yaml.v3"
)

// Config is the top-level struct that holds the entire network configuration.
type Config struct {
	DeviceSecrets  []DeviceSecret  `yaml:"device_secrets"`
	VLANs          []VLAN          `yaml:"vlans"`
	PortChannels   []PortChannel   `yaml:"port-channels"`
	Interfaces     []Interface     `yaml:"interfaces"`
	StaticRoutes   []StaticRoute   `yaml:"static_routes"`
	OSPF           OSPF            `yaml:"ospf"`
	EIGRP          EIGRP           `yaml:"eigrp"`
	VerifyCommands []string        `yaml:"verify_commands"`
	BGP            BGP             `yaml:"bgp"`
	ACLs           []ACL           `yaml:"acls"`
	PrefixLists    []PrefixList    `yaml:"prefix-lists"`
	RouteMaps      []RouteMap      `yaml:"route-maps"`
	DHCP           DHCP            `yaml:"dhcp"`
	HSRP           HSRP            `yaml:"hsrp"`
	VRFs           []VRF           `yaml:"vrfs"`
	SpanningTree   SpanningTree    `yaml:"spanning-tree"`
	QoS            QoS             `yaml:"qos"`
	Logging        Logging         `yaml:"logging"`
	NTP            NTP             `yaml:"ntp"`
	SNMP           SNMP            `yaml:"snmp"`
	Users          []User          `yaml:"users"`
	Authentication Authentication  `yaml:"authentication"`
}

// DeviceSecret holds the path to the credentials in Vault.
type DeviceSecret struct {
	Path string `yaml:"path"`
}

// VLAN defines a Virtual LAN.
type VLAN struct {
	ID   int    `yaml:"id"`
	Name string `yaml:"name"`
}

// PortChannel defines a link aggregation group.
type PortChannel struct {
	ID          int      `yaml:"id"`
	Description string   `yaml:"description"`
	Mode        string   `yaml:"mode"`
	Interfaces  []string `yaml:"interfaces"`
}

// Interface defines a physical or logical network interface.
type Interface struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	IPAddress   string `yaml:"ip_address"`
	SubnetMask  string `yaml:"subnet_mask"`
	Shutdown    bool   `yaml:"shutdown"`
}

// StaticRoute defines a static route. NextHop is an interface{} to allow for simple (string) or complex (map) definitions.
type StaticRoute struct {
	Network      string      `yaml:"prefix"`
	SubnetMask   string      `yaml:"mask"`
	NextHop      interface{} `yaml:"next_hop"`
	AdminAD      int         `yaml:"admin_distance"`
	Metric       int         `yaml:"metric"`
	RouteName    string      `yaml:"name"`
	Multicast    string      `yaml:"multicast"`
	Tag          int         `yaml:"tag"`
	Track        int         `yaml:"track"`
	Vrf          string      `yaml:"vrf"`
	Dhcp         bool        `yaml:"dhcp"`
	TunnelId     int         `yaml:"tunnel-id"`
	Bfd          bool        `yaml:"bfd"`
	NextHopLabel int         `yaml:"next-hop-label"`
	Permanent    bool        `yaml:"permanent"`
}

// OSPFNetwork defines a network to be advertised by OSPF.
type OSPFNetwork struct {
	Address  string `yaml:"network"`
	Wildcard string `yaml:"wildcard_mask"`
	Area     string `yaml:"area"`
}

// OSPFArea defines an OSPF area configuration.
type OSPFArea struct {
	AreaID        string `yaml:"area_id"`
	Authentication string `yaml:"authentication"`
}

// OSPF defines the OSPF routing process configuration.
type OSPF struct {
	ProcessID                 int           `yaml:"process_id"`
	RouterID                  string        `yaml:"router_id"`
	ReferenceBandwidth        int           `yaml:"auto_cost_reference_bandwidth"`
	Authentication            string        `yaml:"authentication"`
	PassiveInterfaces         []string      `yaml:"passive_interfaces"`
	Networks                  []OSPFNetwork `yaml:"networks"`
	DefaultInformationOriginate bool         `yaml:"default_information_originate"`
	DefaultInformationAD      int           `yaml:"default_information_ad"`
	Metric                    int           `yaml:"metric"`
	MetricType                int           `yaml:"metric_type"`
	RouteMap                  string        `yaml:"route-map"`
	AutoCost                  bool          `yaml:"auto-cost"`
	MtuIgnore                 bool          `yaml:"mtu-ignore"`
	DemandCircuit             bool          `yaml:"demand-circuit"`
	LsaGroupPacing            int           `yaml:"lsa-group-pacing"`
	RetransmissionInterval    int           `yaml:"retransmission-interval"`
	TransmitDelay             int           `yaml:"transmit-delay"`
	Priority                  int           `yaml:"priority"`
	Cost                      int           `yaml:"cost"`
	HelloInterval             int           `yaml:"hello-interval"`
	DeadInterval              int           `yaml:"dead-interval"`
	Areas                     []OSPFArea    `yaml:"areas"`
}

// EIGRP defines the EIGRP routing process configuration.
type EIGRP struct {
	ASNumber         int      `yaml:"as_number"`
	RouterID         string   `yaml:"router_id"`
	PassiveInterfaces []string `yaml:"passive_interfaces"`
	Networks         []string `yaml:"networks"`
}

// BGPNeighbor defines a BGP neighbor.
type BGPNeighbor struct {
	IPAddress    string `yaml:"ip_address"`
	RemoteAS     int    `yaml:"remote_as"`
	Description  string `yaml:"description"`
	UpdateSource string `yaml:"update_source"`
}

// BGP defines the BGP routing process configuration.
type BGP struct {
	ASNumber  int           `yaml:"as_number"`
	RouterID  string        `yaml:"router_id"`
	Neighbors []BGPNeighbor `yaml:"neighbors"`
}

// ACLRule defines a single rule in an Access Control List.
type ACLRule struct {
	Action   string `yaml:"action"`
	Protocol string `yaml:"protocol"`
	Source   string `yaml:"source"`
	Dest     string `yaml:"dest"`
	Log      bool   `yaml:"log"`
}

// ACL defines an Access Control List.
type ACL struct {
	Name  string    `yaml:"name"`
	Rules []ACLRule `yaml:"rules"`
}

// PrefixListEntry defines a single entry in a prefix list.
type PrefixListEntry struct {
	Action string `yaml:"action"`
	Prefix string `yaml:"prefix"`
	GE     int    `yaml:"ge,omitempty"`
	LE     int    `yaml:"le,omitempty"`
}

// PrefixList defines a prefix list for filtering routes.
type PrefixList struct {
	Name    string            `yaml:"name"`
	Entries []PrefixListEntry `yaml:"entries"`
}

// RouteMapClause defines a clause in a route map. Match and Set are interfaces to handle complex objects or simple strings.
type RouteMapClause struct {
	Sequence    int         `yaml:"seq"`
	Action      string      `yaml:"action"`
	Description string      `yaml:"description"`
	Match       interface{} `yaml:"match"`
	Set         interface{} `yaml:"set"`
	Continue    int         `yaml:"continue,omitempty"`
}

// RouteMap defines a route map for policy-based routing.
type RouteMap struct {
	Name    string           `yaml:"name"`
	Clauses []RouteMapClause `yaml:"clauses"`
}

// DHCPPool defines a DHCP address pool.
type DHCPPool struct {
	Name          string   `yaml:"name"`
	Network       string   `yaml:"network"`
	SubnetMask    string   `yaml:"subnet_mask"`
	DefaultRouter string   `yaml:"default_router"`
	DNSServers    []string `yaml:"dns_servers"`
	DomainName    string   `yaml:"domain_name"`
	LeaseTime     string   `yaml:"lease_time"`
}

// DHCP defines the DHCP server configuration.
type DHCP struct {
	Enabled bool       `yaml:"enabled"`
	Pools   []DHCPPool `yaml:"pools"`
}

// HSRPGroup defines an HSRP group on an interface.
type HSRPGroup struct {
	ID         int    `yaml:"id"`
	IPAddress  string `yaml:"ip_address"`
	Priority   int    `yaml:"priority"`
	Preempt    bool   `yaml:"preempt"`
	Track      int    `yaml:"track,omitempty"`
	Decrement  int    `yaml:"decrement,omitempty"`
}

// HSRP defines the HSRP configuration.
type HSRP struct {
	Interface string      `yaml:"interface"`
	Groups    []HSRPGroup `yaml:"groups"`
}

// VRF defines a Virtual Routing and Forwarding instance.
type VRF struct {
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
}

// SpanningTree defines the Spanning Tree Protocol configuration.
type SpanningTree struct {
	Mode     string `yaml:"mode"`
	Priority int    `yaml:"priority"`
}

// QoS defines Quality of Service settings.
type QoS struct {
	PolicyMap string `yaml:"policy_map"`
	Interface string `yaml:"interface"`
}

// Logging defines system logging settings.
type Logging struct {
	Server string `yaml:"server"`
	Level  string `yaml:"level"`
}

// NTP defines Network Time Protocol settings.
type NTP struct {
	Servers []string `yaml:"servers"`
}

// SNMP defines Simple Network Management Protocol settings.
type SNMP struct {
	Community string `yaml:"community"`
	Contact   string `yaml:"contact"`
	Location  string `yaml:"location"`
}

// User defines a local user account.
type User struct {
	Username  string `yaml:"username"`
	Password  string `yaml:"password"`
	Privilege int    `yaml:"privilege"`
}

// Authentication defines AAA settings.
type Authentication struct {
	Method string `yaml:"method"`
}

// LoadConfig reads the YAML configuration file and decodes it into a Config struct.
func LoadConfig(filename string) (*Config, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var config Config
	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return nil, err
	}

	return &config, nil
}