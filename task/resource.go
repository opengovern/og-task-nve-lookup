package task

type OutputCVE struct {
	CveID                  string              `json:"cve_id"`
	SourceIdentifier       string              `json:"source_identifier"`
	Published              string              `json:"published"`
	LastModified           string              `json:"last_modified"`
	VulnStatus             string              `json:"vuln_status"`
	Descriptions           []OutputDescription `json:"descriptions"`
	CvssVersion            string              `json:"cvss_version,omitempty"`
	CvssScore              float64             `json:"cvss_score,omitempty"`
	CvssSeverity           string              `json:"cvss_severity,omitempty"`
	CvssAttackVector       string              `json:"cvss_attack_vector,omitempty"`
	CvssAttackComplexity   string              `json:"cvss_attack_complexity,omitempty"`
	CvssPrivilegesRequired string              `json:"cvss_privileges_required,omitempty"`
	CvssUserInteraction    string              `json:"cvss_user_interaction,omitempty"`
	CvssConfImpact         string              `json:"cvss_conf_impact,omitempty"`
	CvssIntegImpact        string              `json:"cvss_integ_impact,omitempty"`
	CvssAvailImpact        string              `json:"cvss_avail_impact,omitempty"`
	Metrics                OutputMetrics       `json:"metrics,omitempty"`
	Weaknesses             []OutputWeakness    `json:"weaknesses"`
	CisaExploitAdd         string              `json:"cisa_exploit_add,omitempty"`
	CisaActionDue          string              `json:"cisa_action_due,omitempty"`
	CisaRequiredAction     string              `json:"cisa_required_action,omitempty"`
	CisaVulnerabilityName  string              `json:"cisa_vulnerability_name,omitempty"`
}

func (r OutputCVE) UniqueID() string {
	return r.CveID
}
