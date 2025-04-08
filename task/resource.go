package task

type TargetCve struct {
	ID                    string           `json:"id"` // UPPERCASE
	SourceIdentifier      string           `json:"source_identifier"`
	Published             string           `json:"published"`
	LastModified          string           `json:"last_modified"`
	VulnStatus            string           `json:"vuln_status"`
	Description           string           `json:"description"`          // Single string
	Metrics               []interface{}    `json:"metrics,omitempty"`    // Flat array
	Weaknesses            []TargetWeakness `json:"weaknesses,omitempty"` // Array, might be empty
	CisaExploitAdd        *string          `json:"cisa_exploit_add,omitempty"`
	CisaActionDue         *string          `json:"cisa_action_due,omitempty"`
	CisaRequiredAction    *string          `json:"cisa_required_action,omitempty"`
	CisaVulnerabilityName *string          `json:"cisa_vulnerability_name,omitempty"`
}

func (r TargetCve) UniqueID() string {
	return r.ID
}
