package mikrotik

import (
	"github.com/StackExchange/dnscontrol/v4/models"
	"github.com/StackExchange/dnscontrol/v4/pkg/rejectif"
)

// AuditRecords returns a list of errors corresponding to the records
// that aren't supported by this provider. If all records are supported,
// an empty list is returned.
func AuditRecords(records []*models.RecordConfig) []error {
	a := rejectif.Auditor{}

	a.Add("MX", rejectif.MxNull) // MX records cannot have null target

	a.Add("TXT", rejectif.TxtIsEmpty) // TXT records cannot be empty

	// MikroTik has a limit on TXT record length
	// The exact limit depends on RouterOS version, but 255 is safe
	a.Add("TXT", rejectif.TxtLongerThan(255))

	return a.Audit(records)
}
