package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/internal/host"
	"github.com/thirdscam/chatanium/internal/portable/store"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

// SetupApprovalSummary shows the operator-facing scope of a setup approval.
// EmptyConfiguration identifies only the canonical no-module configuration.
type SetupApprovalSummary struct {
	Heading            string
	Lines              []string
	EmptyConfiguration bool
}

// DescribeSetupApproval presents a value passed to Confirm during setup. It
// does not grant approval or change the exact plan and digest used by Confirm.
func DescribeSetupApproval(value any) (SetupApprovalSummary, error) {
	switch plan := value.(type) {
	case initPlan:
		return describeSetupInit(plan, false)
	case imagePlan:
		location, err := setupPath(plan.Installation)
		if err != nil {
			return SetupApprovalSummary{}, err
		}
		lines, err := setupImageLines(plan)
		if err != nil {
			return SetupApprovalSummary{}, err
		}
		limits := plan.ImagePlan.Limits
		return SetupApprovalSummary{Heading: "Prepare a module image", Lines: append([]string{
			"Installation: " + location,
			"Guest architecture: " + strconv.QuoteToASCII(plan.ImagePlan.Architecture),
			"Installation disk maximum: " + setupBytes(plan.Limiter),
			fmt.Sprintf("Preparation limits: %d millicores, %s memory, %d tasks, %s deadline.", limits.NanoCPUs/1_000_000, setupBytes(limits.MemoryBytes), limits.Tasks, limits.Deadline),
		}, lines...)}, nil
	case configurationApproval:
		return describeSetupConfiguration(plan)
	case moduleApproval:
		return describeSetupModule(plan)
	case ResetPlan:
		location, err := setupPath(plan.Purge.Root)
		if err != nil {
			return SetupApprovalSummary{}, err
		}
		summary, err := describeSetupInit(plan.Replacement, true)
		if err != nil {
			return SetupApprovalSummary{}, err
		}
		summary.Heading = "Reset Chatanium runtime"
		summary.Lines = append([]string{
			"This permanently deletes the existing installation and retained managed data at " + location + ", including module storage, the image cache, logs, and any managed backups.",
		}, summary.Lines...)
		return summary, nil
	default:
		return SetupApprovalSummary{}, fmt.Errorf("unsupported setup approval type %T", value)
	}
}

func describeSetupInit(plan initPlan, replacement bool) (SetupApprovalSummary, error) {
	location, err := setupPath(plan.Path)
	if err != nil {
		return SetupApprovalSummary{}, err
	}
	label := "Installation: "
	if replacement {
		label = "Replacement installation: "
	}
	target := plan.Bundle.Target
	lines := []string{
		label + location,
		fmt.Sprintf("Target: %s (%s); GVX engine %s.", strconv.QuoteToASCII(target.OS+"/"+target.Arch), strconv.QuoteToASCII(target.Backend), strconv.QuoteToASCII(plan.Bundle.Engine.Release)),
		fmt.Sprintf("Disk maximum: %s total; %s code and metadata; %s logs and control files per run.", setupBytes(plan.BudgetBytes), setupBytes(plan.MetadataBytes), setupBytes(plan.LogBytes)),
		fmt.Sprintf("Host data bounds: %s uploads; %s Discord ownership data.", setupBytes(plan.UploadBytes), setupBytes(plan.DiscordBytes)),
	}
	if first := plan.FirstModule; first != nil {
		image, err := setupImageLines(first.Image)
		if err != nil {
			return SetupApprovalSummary{}, err
		}
		lines = append(lines, fmt.Sprintf("Initial module: %s (guest UID %d, GID %d).", strconv.QuoteToASCII(first.ModuleID), first.UID, first.GID))
		lines = append(lines, image...)
		lines = append(lines, "The module's launch, resources and grants require separate approval.")
	} else {
		lines = append(lines, "No modules will be installed or started.")
	}
	return SetupApprovalSummary{Heading: "Set up Chatanium runtime", Lines: lines}, nil
}

func setupPath(path string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", errors.New("setup approval contains a non-absolute path")
	}
	return strconv.QuoteToASCII(path), nil
}

func setupBytes(n int64) string {
	for _, unit := range [...]struct {
		bytes int64
		label string
	}{{1 << 50, "PiB"}, {1 << 40, "TiB"}, {1 << 30, "GiB"}, {1 << 20, "MiB"}, {1 << 10, "KiB"}} {
		if n >= unit.bytes {
			if n%unit.bytes == 0 {
				return fmt.Sprintf("%d %s", n/unit.bytes, unit.label)
			}
			return fmt.Sprintf("%.2f %s (%d B)", float64(n)/float64(unit.bytes), unit.label, n)
		}
	}
	return fmt.Sprintf("%d B", n)
}

func setupImageLines(plan imagePlan) ([]string, error) {
	source := plan.ImagePlan.Source
	var lines []string
	switch source.Kind {
	case "registry":
		if _, err := setupRegistryURL(source.Reference); err != nil {
			return nil, err
		}
		lines = append(lines, "Image source: pinned registry repository "+strconv.QuoteToASCII(source.Reference))
		if source.TokenURL != "" {
			token, err := setupRegistryURL(source.TokenURL)
			if err != nil {
				return nil, err
			}
			lines = append(lines, "Registry token authority: "+strconv.QuoteToASCII(token.Host))
		}
		if len(source.RedirectHosts) != 0 {
			lines = append(lines, "Registry redirect hosts: "+setupQuotedList(source.RedirectHosts, 8))
		}
	case "oci-archive", "docker-archive":
		archive, err := setupPath(plan.Archive)
		if err != nil {
			return nil, err
		}
		kind := "OCI"
		if source.Kind == "docker-archive" {
			kind = "Docker"
		}
		lines = append(lines, "Image source: "+kind+" archive "+archive)
	default:
		return nil, errors.New("unsupported setup image source")
	}
	return append(lines, fmt.Sprintf("Image disk maxima: %s preparation; %s cache.", setupBytes(plan.WorkBytes), setupBytes(plan.CacheBytes))), nil
}

func setupRegistryURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.ForceQuery || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("cannot display setup registry endpoint safely")
	}
	return u, nil
}

func describeSetupConfiguration(approval configurationApproval) (SetupApprovalSummary, error) {
	plan := approval.Plan
	location, err := setupPath(plan.Installation)
	if err != nil {
		return SetupApprovalSummary{}, err
	}
	summary := SetupApprovalSummary{Heading: "Publish stopped configuration", Lines: []string{
		"Installation: " + location,
		"Installation disk maximum: " + setupBytes(plan.BudgetBytes),
	}}
	if len(plan.Reviews) == 0 {
		// Configure has already verified that the only permitted zero-review
		// configuration is exactly the canonical module-free default.
		summary.EmptyConfiguration = true
		summary.Lines = append(summary.Lines, "Default idle configuration: no modules, backends or module network access.")
		return summary, nil
	}
	cfg := approval.display
	if cfg == nil || len(cfg.Modules) != len(plan.Reviews) {
		return SetupApprovalSummary{}, errors.New("missing setup configuration review details")
	}
	summary.Lines = append(summary.Lines, fmt.Sprintf("Modules to review separately: %d; configured backends: %d.", len(plan.Reviews), len(cfg.Backends)))
	var sources, bindings int
	for _, backend := range cfg.Backends {
		sources += len(backend.SecretSources)
	}
	for _, module := range cfg.Modules {
		bindings += len(module.CredentialBindings)
	}
	if sources != 0 || bindings != 0 {
		summary.Lines = append(summary.Lines, fmt.Sprintf("Credential sources: %d; provisioned module credential bindings: %d (values not shown).", sources, bindings))
	}
	if discord, ok := cfg.Backends["discord"]; ok {
		var settings struct {
			Intents discordgo.Intent `json:"intents"`
		}
		if json.Unmarshal(discord.Config, &settings) != nil {
			return SetupApprovalSummary{}, errors.New("cannot describe Discord gateway intents")
		}
		var privileged []string
		if settings.Intents&discordgo.IntentGuildMembers != 0 {
			privileged = append(privileged, "GUILD_MEMBERS")
		}
		if settings.Intents&discordgo.IntentGuildPresences != 0 {
			privileged = append(privileged, "GUILD_PRESENCES")
		}
		if settings.Intents&discordgo.IntentMessageContent != 0 {
			privileged = append(privileged, "MESSAGE_CONTENT")
		}
		if len(privileged) != 0 {
			summary.Lines = append(summary.Lines, "Privileged Discord gateway intents: "+strings.Join(privileged, ", "))
		}
	}
	return summary, nil
}

func describeSetupModule(approval moduleApproval) (SetupApprovalSummary, error) {
	var image imagePlan
	var review struct {
		Launch struct {
			UID       uint32              `json:"uid"`
			GID       uint32              `json:"gid"`
			Resources host.ResourceLimits `json:"resources"`
		} `json:"launch"`
		Grant   json.RawMessage      `json:"grant"`
		Network store.NetworkProfile `json:"network"`
	}
	var grant wire.Grants
	if json.Unmarshal(approval.Acquisition, &image) != nil || json.Unmarshal(approval.Review, &review) != nil ||
		protojson.Unmarshal(review.Grant, &grant) != nil || grant.ResourceLimits == nil {
		return SetupApprovalSummary{}, errors.New("cannot describe module approval")
	}
	location, err := setupPath(image.Installation)
	if err != nil {
		return SetupApprovalSummary{}, err
	}
	imageLines, err := setupImageLines(image)
	if err != nil {
		return SetupApprovalSummary{}, err
	}
	network, err := setupNetworkLine(review.Network)
	if err != nil {
		return SetupApprovalSummary{}, err
	}
	limits := review.Launch.Resources
	lines := append([]string{"Installation: " + location}, imageLines...)
	lines = append(lines,
		fmt.Sprintf("Isolated, unprivileged launch: guest UID %d, GID %d.", review.Launch.UID, review.Launch.GID),
		fmt.Sprintf("Resource maxima: %d millicores, %s memory, %d tasks; %s persistent, %s scratch.", limits.NanoCPUs/1_000_000, setupBytes(limits.MemoryBytes), limits.Pids, setupBytes(limits.PersistentBytes), setupBytes(limits.ScratchBytes)),
		network,
	)
	lines = append(lines, setupGrantLines(&grant)...)
	return SetupApprovalSummary{Heading: "Review module " + strconv.QuoteToASCII(approval.Module), Lines: lines}, nil
}

func setupNetworkLine(profile store.NetworkProfile) (string, error) {
	switch profile.Mode {
	case store.NetworkNone:
		return "Network grant: NONE (no module network access).", nil
	case store.NetworkPublic:
		rate := func(bps uint64, unlimited bool) string {
			if unlimited {
				return "unlimited"
			}
			return fmt.Sprintf("%d bit/s", bps)
		}
		return fmt.Sprintf("Network grant: public internet egress (%s); TX %s, RX %s; DNS %s; %d configured address exclusions.",
			strconv.QuoteToASCII(profile.AddressFamily), rate(profile.NetTXBPS, profile.AllowUnlimitedTX), rate(profile.NetRXBPS, profile.AllowUnlimitedRX),
			setupQuotedList(profile.DNSServers, 4), len(profile.ExcludedAddresses)), nil
	default:
		return "", errors.New("unsupported setup module network policy")
	}
}

func setupQuotedList(values []string, limit int) string {
	var list []string
	for _, value := range values[:min(len(values), limit)] {
		list = append(list, strconv.QuoteToASCII(value))
	}
	if len(values) > limit {
		list = append(list, fmt.Sprintf("and %d more", len(values)-limit))
	}
	return strings.Join(list, ", ")
}

func setupGrantLines(grant *wire.Grants) []string {
	const maxNames = 8
	var names []string
	var total, broad int
	add := func(backend string, caps []*wire.CapabilityGrant) {
		for _, capability := range caps {
			total++
			wide := false
			for _, scope := range capability.GetResourceScopes() {
				if scope.GetAllResources() {
					wide = true
					broad++
					break
				}
			}
			if len(names) < maxNames {
				name := backend + strconv.QuoteToASCII(capability.GetName())
				if wide {
					name += " (all resources)"
				}
				names = append(names, name)
			}
		}
	}
	add("", grant.CoreCapabilities)
	for _, backend := range grant.Backends {
		add(strconv.QuoteToASCII(backend.GetBackendId())+":", backend.GetCapabilities())
	}
	if total == 0 {
		return []string{"Capability grants: none."}
	}
	if total > len(names) {
		names = append(names, fmt.Sprintf("and %d more", total-len(names)))
	}
	lines := []string{"Capability grants (approved ceilings): " + strings.Join(names, ", ")}
	if broad != 0 {
		lines = append(lines, fmt.Sprintf("Broad grants: %d capabilities have all-resource scope (backend constraints still apply).", broad))
	}
	return lines
}
