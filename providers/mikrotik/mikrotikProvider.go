package mikrotik

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/diff2"
	"github.com/StackExchange/dnscontrol/v4/pkg/printer"
	"github.com/StackExchange/dnscontrol/v4/pkg/providers"
)

/*
MikroTik RouterOS DNS provider:

Info required in `creds.json`:
   - host: IP address or hostname of the MikroTik device
   - username: API username (default: admin)
   - password: API password

Optional settings:
   - port: API port (default: 8728 for plain, 8729 for TLS)
   - use_tls: Use TLS connection (default: false)
   - insecure: Skip TLS certificate verification (default: false)
   - timeout: Connection timeout in seconds (default: 10)

Example creds.json:
{
  "mikrotik": {
    "TYPE": "MIKROTIK",
    "host": "192.168.88.1",
    "username": "admin",
    "password": "admin"
  }
}

Note: This provider manages static DNS entries on MikroTik RouterOS devices.
It uses the RouterOS API to communicate with the device.
The "domain" in dnscontrol is used as a filter - only records ending with
that domain will be managed.
*/

var features = providers.DocumentationNotes{
	// The default for unlisted capabilities is 'Cannot'.
	// See providers/capabilities.go for the entire list of capabilities.
	providers.CanAutoDNSSEC:          providers.Cannot(),
	providers.CanConcur:              providers.Can(),
	providers.CanGetZones:            providers.Cannot("MikroTik doesn't have zone concept"),
	providers.CanUseAlias:            providers.Cannot(),
	providers.CanUseCAA:              providers.Cannot(),
	providers.CanUseDHCID:            providers.Cannot(),
	providers.CanUseDNAME:            providers.Cannot(),
	providers.CanUseDNSKEY:           providers.Cannot(),
	providers.CanUseDS:               providers.Cannot(),
	providers.CanUseHTTPS:            providers.Cannot(),
	providers.CanUseLOC:              providers.Cannot(),
	providers.CanUseNAPTR:            providers.Cannot(),
	providers.CanUsePTR:              providers.Cannot(),
	providers.CanUseSOA:              providers.Cannot(),
	providers.CanUseSRV:              providers.Can(),
	providers.CanUseSSHFP:            providers.Cannot(),
	providers.CanUseSVCB:             providers.Cannot(),
	providers.CanUseTLSA:             providers.Cannot(),
	providers.DocCreateDomains:       providers.Cannot("MikroTik doesn't have zone concept"),
	providers.DocDualHost:            providers.Cannot(),
	providers.DocOfficiallySupported: providers.Cannot(),
}

func init() {
	const providerName = "MIKROTIK"
	const providerMaintainer = "@zupolgec"

	fns := providers.DspFuncs{
		Initializer:   NewMikroTik,
		RecordAuditor: AuditRecords,
	}
	providers.RegisterDomainServiceProviderType(providerName, fns, features)
	providers.RegisterMaintainer(providerName, providerMaintainer)
}

// NewMikroTik creates a new MikroTik DNS provider
func NewMikroTik(m map[string]string, metadata json.RawMessage) (providers.DNSServiceProvider, error) {
	if m["host"] == "" {
		return nil, errors.New("missing MikroTik host")
	}

	username := m["username"]
	if username == "" {
		username = "admin"
	}

	password := m["password"]
	if password == "" {
		return nil, errors.New("missing MikroTik password")
	}

	// Parse port
	port := DefaultAPIPort
	useTLS := false
	if m["use_tls"] == "true" {
		useTLS = true
		port = DefaultAPITLSPort
	}
	if m["port"] != "" {
		if p, err := strconv.Atoi(m["port"]); err == nil {
			port = p
		}
	}

	insecure := m["insecure"] == "true"

	// Parse timeout
	timeout := 10 * time.Second
	if m["timeout"] != "" {
		if t, err := strconv.Atoi(m["timeout"]); err == nil {
			timeout = time.Duration(t) * time.Second
		}
	}

	api := newClient(m["host"], port, username, password, useTLS, insecure, timeout)
	return api, nil
}

// GetNameservers returns the nameservers for a domain.
// MikroTik doesn't have a nameserver concept for zones, so we return empty.
func (c *mikrotikProvider) GetNameservers(domain string) ([]*models.Nameserver, error) {
	return nil, nil
}

// GetZoneRecords gets the records of a zone and returns them in RecordConfig format.
// Since MikroTik doesn't have zones, we filter records by domain suffix.
func (c *mikrotikProvider) GetZoneRecords(domain string, meta map[string]string) (models.Records, error) {
	records, err := c.getStaticDNSRecords()
	if err != nil {
		return nil, err
	}

	var existingRecords []*models.RecordConfig
	for _, r := range records {
		// Skip disabled records
		if r.Disabled {
			continue
		}

		// Filter by domain - only include records that belong to this domain
		if !belongsToDomain(r.Name, domain) {
			continue
		}

		rc, err := toRecordConfig(domain, r)
		if err != nil {
			printer.Warnf("Skipping record %s: %v\n", r.Name, err)
			continue
		}
		if rc != nil {
			existingRecords = append(existingRecords, rc)
		}
	}

	return existingRecords, nil
}

// GetZoneRecordsCorrections returns a list of corrections that will turn existing records into dc.Records
func (c *mikrotikProvider) GetZoneRecordsCorrections(dc *models.DomainConfig, existingRecords models.Records) ([]*models.Correction, int, error) {
	var corrections []*models.Correction

	// MikroTik doesn't support NS records at apex the same way, filter them
	filterUnsupportedRecords(dc)

	instructions, actualChangeCount, err := diff2.ByRecord(existingRecords, dc, nil)
	if err != nil {
		return nil, 0, err
	}

	for _, inst := range instructions {
		switch inst.Type {
		case diff2.REPORT:
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
			})

		case diff2.CREATE:
			rec := inst.New[0]
			mkRecord := toMikroTikRecord(dc.Name, rec)
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
				F: func() error {
					return c.addStaticDNSRecord(mkRecord)
				},
			})

		case diff2.CHANGE:
			oldRec := inst.Old[0]
			newRec := inst.New[0]
			oldMK := oldRec.Original.(*StaticDNSRecord)
			newMK := toMikroTikRecord(dc.Name, newRec)
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
				F: func() error {
					return c.updateStaticDNSRecord(oldMK.ID, newMK)
				},
			})

		case diff2.DELETE:
			oldRec := inst.Old[0]
			oldMK := oldRec.Original.(*StaticDNSRecord)
			corrections = append(corrections, &models.Correction{
				Msg: inst.MsgsJoined,
				F: func() error {
					return c.deleteStaticDNSRecord(oldMK.ID)
				},
			})

		default:
			panic(fmt.Sprintf("unhandled inst.Type %s", inst.Type))
		}
	}

	return corrections, actualChangeCount, nil
}

// belongsToDomain checks if a record name belongs to the given domain
func belongsToDomain(name, domain string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	if name == domain {
		return true
	}
	return strings.HasSuffix(name, "."+domain)
}

// toRecordConfig converts a MikroTik DNS record to a RecordConfig
func toRecordConfig(domain string, r *StaticDNSRecord) (*models.RecordConfig, error) {
	rc := &models.RecordConfig{
		TTL:      parseTTL(r.TTL),
		Original: r,
	}

	// Determine the label from the name
	label := extractLabel(r.Name, domain)
	rc.SetLabel(label, domain)

	// Handle different record types
	switch r.Type {
	case RecordTypeA:
		rc.Type = "A"
		if err := rc.SetTarget(r.Address); err != nil {
			return nil, err
		}

	case RecordTypeAAAA:
		rc.Type = "AAAA"
		if err := rc.SetTarget(r.Address); err != nil {
			return nil, err
		}

	case RecordTypeCNAME:
		rc.Type = "CNAME"
		target := ensureTrailingDot(r.CName)
		if err := rc.SetTarget(target); err != nil {
			return nil, err
		}

	case RecordTypeTXT:
		rc.Type = "TXT"
		if err := rc.SetTargetTXT(r.Text); err != nil {
			return nil, err
		}

	case RecordTypeMX:
		rc.Type = "MX"
		rc.MxPreference = r.MXPreference
		target := ensureTrailingDot(r.MXExchange)
		if err := rc.SetTarget(target); err != nil {
			return nil, err
		}

	case RecordTypeNS:
		rc.Type = "NS"
		target := ensureTrailingDot(r.NS)
		if err := rc.SetTarget(target); err != nil {
			return nil, err
		}

	case RecordTypeSRV:
		rc.Type = "SRV"
		rc.SrvPriority = r.SRVPriority
		rc.SrvWeight = r.SRVWeight
		rc.SrvPort = r.SRVPort
		target := ensureTrailingDot(r.SRVTarget)
		if err := rc.SetTarget(target); err != nil {
			return nil, err
		}

	default:
		// Skip unsupported record types (FWD, NXDOMAIN, etc.)
		return nil, nil
	}

	return rc, nil
}

// toMikroTikRecord converts a RecordConfig to a MikroTik DNS record
func toMikroTikRecord(domain string, rc *models.RecordConfig) *StaticDNSRecord {
	rec := &StaticDNSRecord{
		Name: rc.GetLabelFQDN(),
		TTL:  formatTTL(rc.TTL),
	}

	switch rc.Type {
	case "A":
		rec.Type = RecordTypeA
		rec.Address = rc.GetTargetField()

	case "AAAA":
		rec.Type = RecordTypeAAAA
		rec.Address = rc.GetTargetField()

	case "CNAME":
		rec.Type = RecordTypeCNAME
		rec.CName = strings.TrimSuffix(rc.GetTargetField(), ".")

	case "TXT":
		rec.Type = RecordTypeTXT
		rec.Text = rc.GetTargetTXTJoined()

	case "MX":
		rec.Type = RecordTypeMX
		rec.MXPreference = rc.MxPreference
		rec.MXExchange = strings.TrimSuffix(rc.GetTargetField(), ".")

	case "NS":
		rec.Type = RecordTypeNS
		rec.NS = strings.TrimSuffix(rc.GetTargetField(), ".")

	case "SRV":
		rec.Type = RecordTypeSRV
		rec.SRVPriority = rc.SrvPriority
		rec.SRVWeight = rc.SrvWeight
		rec.SRVPort = rc.SrvPort
		rec.SRVTarget = strings.TrimSuffix(rc.GetTargetField(), ".")
	}

	return rec
}

// filterUnsupportedRecords removes record types that MikroTik doesn't support
func filterUnsupportedRecords(dc *models.DomainConfig) {
	newList := make([]*models.RecordConfig, 0, len(dc.Records))
	for _, rec := range dc.Records {
		// MikroTik supports: A, AAAA, CNAME, MX, NS, SRV, TXT
		switch rec.Type {
		case "A", "AAAA", "CNAME", "MX", "NS", "SRV", "TXT":
			newList = append(newList, rec)
		default:
			printer.Warnf("MIKROTIK does not support %s records. %s will be skipped.\n", rec.Type, rec.GetLabel())
		}
	}
	dc.Records = newList
}

// extractLabel extracts the label from a FQDN given the domain
func extractLabel(fqdn, domain string) string {
	fqdn = strings.ToLower(strings.TrimSuffix(fqdn, "."))
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	if fqdn == domain {
		return "@"
	}

	if strings.HasSuffix(fqdn, "."+domain) {
		return strings.TrimSuffix(fqdn, "."+domain)
	}

	return fqdn
}

// ensureTrailingDot adds a trailing dot if not present
func ensureTrailingDot(s string) string {
	if s == "" {
		return s
	}
	if !strings.HasSuffix(s, ".") {
		return s + "."
	}
	return s
}
