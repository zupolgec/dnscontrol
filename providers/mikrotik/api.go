package mikrotik

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/go-routeros/routeros/v3"
)

// mikrotikProvider holds the API configuration (no persistent connection for thread safety)
type mikrotikProvider struct {
	host     string
	port     int
	username string
	password string
	useTLS   bool
	insecure bool
	timeout  time.Duration
}

// newClient creates a new MikroTik API client
func newClient(host string, port int, username, password string, useTLS, insecure bool, timeout time.Duration) *mikrotikProvider {
	return &mikrotikProvider{
		host:     host,
		port:     port,
		username: username,
		password: password,
		useTLS:   useTLS,
		insecure: insecure,
		timeout:  timeout,
	}
}

// connect establishes a new connection to the MikroTik device
// Caller is responsible for closing the returned client
func (c *mikrotikProvider) connect() (*routeros.Client, error) {
	address := fmt.Sprintf("%s:%d", c.host, c.port)

	var client *routeros.Client
	var err error

	if c.useTLS {
		// For TLS, we need to dial with timeout first, then wrap with TLS
		dialer := &net.Dialer{Timeout: c.timeout}
		conn, dialErr := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: c.insecure,
		})
		if dialErr != nil {
			return nil, fmt.Errorf("failed to connect to MikroTik at %s: %w", address, dialErr)
		}
		client, err = routeros.NewClient(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to create RouterOS client: %w", err)
		}
		err = client.Login(c.username, c.password)
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to login to MikroTik: %w", err)
		}
	} else {
		// For plain TCP, dial with timeout
		conn, dialErr := net.DialTimeout("tcp", address, c.timeout)
		if dialErr != nil {
			return nil, fmt.Errorf("failed to connect to MikroTik at %s: %w", address, dialErr)
		}
		client, err = routeros.NewClient(conn)
		if err != nil {
			conn.Close()
			return nil, fmt.Errorf("failed to create RouterOS client: %w", err)
		}
		err = client.Login(c.username, c.password)
		if err != nil {
			client.Close()
			return nil, fmt.Errorf("failed to login to MikroTik: %w", err)
		}
	}

	return client, nil
}

// getStaticDNSRecords retrieves all static DNS records from the device
func (c *mikrotikProvider) getStaticDNSRecords() ([]*StaticDNSRecord, error) {
	client, err := c.connect()
	if err != nil {
		return nil, err
	}
	defer client.Close()

	reply, err := client.Run("/ip/dns/static/print")
	if err != nil {
		return nil, fmt.Errorf("failed to get DNS records: %w", err)
	}

	var records []*StaticDNSRecord
	for _, re := range reply.Re {
		record := &StaticDNSRecord{
			ID: re.Map[".id"],
		}

		// Parse record fields
		if name, ok := re.Map["name"]; ok {
			record.Name = name
		}
		if address, ok := re.Map["address"]; ok {
			record.Address = address
		}
		if recordType, ok := re.Map["type"]; ok {
			record.Type = recordType
		} else {
			// Default type is A if address is set, otherwise check other fields
			if record.Address != "" {
				record.Type = "A"
			}
		}
		if cname, ok := re.Map["cname"]; ok {
			record.CName = cname
			if record.Type == "" {
				record.Type = "CNAME"
			}
		}
		if text, ok := re.Map["text"]; ok {
			record.Text = text
			if record.Type == "" {
				record.Type = "TXT"
			}
		}
		if mxExchange, ok := re.Map["mx-exchange"]; ok {
			record.MXExchange = mxExchange
			if record.Type == "" {
				record.Type = "MX"
			}
		}
		if mxPref, ok := re.Map["mx-preference"]; ok {
			if pref, err := strconv.ParseUint(mxPref, 10, 16); err == nil {
				record.MXPreference = uint16(pref)
			}
		}
		if ns, ok := re.Map["ns"]; ok {
			record.NS = ns
			if record.Type == "" {
				record.Type = "NS"
			}
		}
		if srvTarget, ok := re.Map["srv-target"]; ok {
			record.SRVTarget = srvTarget
			if record.Type == "" {
				record.Type = "SRV"
			}
		}
		if srvPort, ok := re.Map["srv-port"]; ok {
			if port, err := strconv.ParseUint(srvPort, 10, 16); err == nil {
				record.SRVPort = uint16(port)
			}
		}
		if srvPriority, ok := re.Map["srv-priority"]; ok {
			if priority, err := strconv.ParseUint(srvPriority, 10, 16); err == nil {
				record.SRVPriority = uint16(priority)
			}
		}
		if srvWeight, ok := re.Map["srv-weight"]; ok {
			if weight, err := strconv.ParseUint(srvWeight, 10, 16); err == nil {
				record.SRVWeight = uint16(weight)
			}
		}
		if ttl, ok := re.Map["ttl"]; ok {
			record.TTL = ttl
		}
		if comment, ok := re.Map["comment"]; ok {
			record.Comment = comment
		}
		if disabled, ok := re.Map["disabled"]; ok {
			record.Disabled = disabled == "true"
		}
		if regexp, ok := re.Map["regexp"]; ok {
			record.Regexp = regexp
		}
		if matchSubdomain, ok := re.Map["match-subdomain"]; ok {
			record.MatchSubdomain = matchSubdomain == "true"
		}
		if addressList, ok := re.Map["address-list"]; ok {
			record.AddressList = addressList
		}

		records = append(records, record)
	}

	return records, nil
}

// addStaticDNSRecord adds a new static DNS record
func (c *mikrotikProvider) addStaticDNSRecord(record *StaticDNSRecord) error {
	client, err := c.connect()
	if err != nil {
		return err
	}
	defer client.Close()

	args := c.buildRecordArgs(record)
	args = append([]string{"/ip/dns/static/add"}, args...)

	_, err = client.Run(args...)
	if err != nil {
		return fmt.Errorf("failed to add DNS record: %w", err)
	}

	return nil
}

// updateStaticDNSRecord updates an existing static DNS record
func (c *mikrotikProvider) updateStaticDNSRecord(id string, record *StaticDNSRecord) error {
	client, err := c.connect()
	if err != nil {
		return err
	}
	defer client.Close()

	args := c.buildRecordArgs(record)
	args = append([]string{"/ip/dns/static/set", "=.id=" + id}, args...)

	_, err = client.Run(args...)
	if err != nil {
		return fmt.Errorf("failed to update DNS record: %w", err)
	}

	return nil
}

// deleteStaticDNSRecord deletes a static DNS record by ID
func (c *mikrotikProvider) deleteStaticDNSRecord(id string) error {
	client, err := c.connect()
	if err != nil {
		return err
	}
	defer client.Close()

	_, err = client.Run("/ip/dns/static/remove", "=.id="+id)
	if err != nil {
		return fmt.Errorf("failed to delete DNS record: %w", err)
	}

	return nil
}

// buildRecordArgs converts a StaticDNSRecord to RouterOS API arguments
func (c *mikrotikProvider) buildRecordArgs(record *StaticDNSRecord) []string {
	var args []string

	if record.Name != "" {
		args = append(args, "=name="+record.Name)
	}

	// Set type-specific fields
	switch record.Type {
	case "A", "AAAA":
		if record.Address != "" {
			args = append(args, "=address="+record.Address)
		}
		// Type field needed for AAAA to distinguish from A
		if record.Type == "AAAA" {
			args = append(args, "=type=AAAA")
		}
	case "CNAME":
		if record.CName != "" {
			args = append(args, "=cname="+record.CName)
		}
		args = append(args, "=type=CNAME")
	case "TXT":
		if record.Text != "" {
			args = append(args, "=text="+record.Text)
		}
		args = append(args, "=type=TXT")
	case "MX":
		if record.MXExchange != "" {
			args = append(args, "=mx-exchange="+record.MXExchange)
		}
		args = append(args, fmt.Sprintf("=mx-preference=%d", record.MXPreference))
		args = append(args, "=type=MX")
	case "NS":
		if record.NS != "" {
			args = append(args, "=ns="+record.NS)
		}
		args = append(args, "=type=NS")
	case "SRV":
		if record.SRVTarget != "" {
			args = append(args, "=srv-target="+record.SRVTarget)
		}
		args = append(args, fmt.Sprintf("=srv-port=%d", record.SRVPort))
		args = append(args, fmt.Sprintf("=srv-priority=%d", record.SRVPriority))
		args = append(args, fmt.Sprintf("=srv-weight=%d", record.SRVWeight))
		args = append(args, "=type=SRV")
	}

	if record.TTL != "" {
		args = append(args, "=ttl="+record.TTL)
	}

	if record.Comment != "" {
		args = append(args, "=comment="+record.Comment)
	}

	if record.Disabled {
		args = append(args, "=disabled=yes")
	}

	return args
}

// parseTTL parses a MikroTik TTL string to seconds
// MikroTik uses formats like "1d", "1h", "1m", "1s" or combinations like "1d00:00:00"
func parseTTL(ttlStr string) uint32 {
	if ttlStr == "" {
		return 0
	}

	// Try parsing as duration
	duration, err := time.ParseDuration(normalizeRouterOSDuration(ttlStr))
	if err == nil {
		return uint32(duration.Seconds())
	}

	// Try parsing as plain number (seconds)
	if seconds, err := strconv.ParseUint(ttlStr, 10, 32); err == nil {
		return uint32(seconds)
	}

	return 0
}

// normalizeRouterOSDuration converts RouterOS duration format to Go duration format
// RouterOS: "1d00:00:00" or "1d" or "1h" etc.
// Go: "24h" or "1h" etc.
func normalizeRouterOSDuration(s string) string {
	// Handle common formats
	// "1d00:00:00" -> "24h"
	// "1d" -> "24h"
	// Already in Go format: "1h", "1m", "1s"

	var totalSeconds int64

	// Check for days
	for i := 0; i < len(s); i++ {
		if s[i] == 'd' {
			days, err := strconv.ParseInt(s[:i], 10, 64)
			if err == nil {
				totalSeconds += days * 24 * 60 * 60
			}
			s = s[i+1:]
			break
		}
	}

	// Check for time format HH:MM:SS
	if len(s) > 0 && s[0] >= '0' && s[0] <= '9' {
		var hours, minutes, seconds int64
		n, err := fmt.Sscanf(s, "%d:%d:%d", &hours, &minutes, &seconds)
		if err == nil && n == 3 {
			totalSeconds += hours*60*60 + minutes*60 + seconds
		} else {
			// Try parsing remaining as Go duration
			d, err := time.ParseDuration(s)
			if err == nil {
				totalSeconds += int64(d.Seconds())
			}
		}
	}

	if totalSeconds > 0 {
		return fmt.Sprintf("%ds", totalSeconds)
	}

	return s
}

// formatTTL converts seconds to MikroTik TTL format
func formatTTL(seconds uint32) string {
	if seconds == 0 {
		return ""
	}
	return fmt.Sprintf("%ds", seconds)
}
