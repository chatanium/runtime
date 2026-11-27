package discordacl

const (
	Show     = "acl.show"
	Guilds   = "acl.guilds"
	Channels = "acl.channels"
	Preview  = "acl.preview"
	Apply    = "acl.apply"
)

type Query struct {
	Module   string `json:"module"`
	GuildID  string `json:"guild_id,omitempty"`
	Policy   Policy `json:"policy"`
	Approval string `json:"approval,omitempty"`
}

type Status struct {
	Policy  Policy   `json:"policy"`
	Managed bool     `json:"managed"`
	Labels  []string `json:"labels,omitempty"`
}

type Choice struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type Plan struct {
	Before Status `json:"before"`
	After  Status `json:"after"`
	Digest string `json:"digest"`
}
