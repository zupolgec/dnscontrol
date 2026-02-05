package mikrotik

// StaticDNSRecord represents a static DNS record in MikroTik RouterOS
type StaticDNSRecord struct {
	ID   string // Internal MikroTik ID (.id)
	Name string // DNS name (hostname)

	// Record type: A, AAAA, CNAME, FWD, MX, NS, NXDOMAIN, SRV, TXT
	Type string

	// A/AAAA records
	Address string

	// CNAME records
	CName string

	// TXT records
	Text string

	// MX records
	MXExchange   string
	MXPreference uint16

	// NS records
	NS string

	// SRV records
	SRVTarget   string
	SRVPort     uint16
	SRVPriority uint16
	SRVWeight   uint16

	// Common fields
	TTL      string // TTL in RouterOS format (e.g., "1d", "1h", "300s")
	Comment  string
	Disabled bool

	// Advanced fields (not commonly used for DNS provider)
	Regexp         string
	MatchSubdomain bool
	AddressList    string
}

// Supported record types in MikroTik RouterOS DNS
const (
	RecordTypeA        = "A"
	RecordTypeAAAA     = "AAAA"
	RecordTypeCNAME    = "CNAME"
	RecordTypeFWD      = "FWD" // Forward to another DNS server
	RecordTypeMX       = "MX"
	RecordTypeNS       = "NS"
	RecordTypeNXDOMAIN = "NXDOMAIN" // Return NXDOMAIN for this name
	RecordTypeSRV      = "SRV"
	RecordTypeTXT      = "TXT"
)

// Default ports for MikroTik API
const (
	DefaultAPIPort    = 8728
	DefaultAPITLSPort = 8729
)
