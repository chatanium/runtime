//go:build linux

package host

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
)

type networkHook struct {
	table, chain string
	args         []string
}

func networkHooks(r NetworkRecord, family int) []networkHook {
	f, i, n := networkChains(r)
	hooks := []networkHook{{"filter", "INPUT", []string{"-i", r.HostInterface, "-j", i}}, {"filter", "OUTPUT", []string{"-o", r.HostInterface, "-j", i}}, {"filter", "FORWARD", []string{"-i", r.HostInterface, "-j", f}}, {"filter", "FORWARD", []string{"-o", r.HostInterface, "-j", f}}}
	if family == 4 || r.Profile == NetworkPublicDual {
		source, uplink := r.PeerIPv4, r.Uplink4
		if family == 6 {
			source, uplink = r.PeerIPv6, r.Uplink6
		}
		bits := "/32"
		if family == 6 {
			bits = "/128"
		}
		hooks = append(hooks, networkHook{"nat", "POSTROUTING", []string{"-s", source + bits, "-o", uplink, "-j", n}})
	}
	return hooks
}
func networkChainInventory(raw []byte, chain string) string {
	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, "-N "+chain) || strings.HasPrefix(line, "-A "+chain+" ") {
			rows = append(rows, line)
		}
	}
	return strings.Join(rows, "\n")
}
func (n *Network) createFirewall(ctx context.Context, a *networkAllocation) error {
	r := a.Record
	f, i, nat := networkChains(r)
	for _, family := range []int{4, 6} {
		chains := []struct{ table, name string }{{"filter", f}, {"filter", i}}
		if family == 4 || r.Profile == NetworkPublicDual {
			chains = append(chains, struct{ table, name string }{"nat", nat})
		}
		for _, chain := range chains {
			raw, err := n.tables(ctx, family, "", chain.table, "-S")
			if err != nil {
				return err
			}
			if networkChainInventory(raw, chain.name) != "" {
				return errors.New("network chain collision; refusing foreign chain adoption")
			}
			key := fmt.Sprintf("intent/%d/%s/%s", family, chain.table, chain.name)
			a.Rules[key] = "SUBMITTED"
			if err = n.save(ctx, a); err != nil {
				return err
			}
			if _, err = n.tables(ctx, family, "", chain.table, "-N", chain.name); err != nil {
				return err
			}
			observed, err := n.tables(ctx, family, "", chain.table, "-S")
			if err != nil {
				return err
			}
			identity := networkChainInventory(observed, chain.name)
			if identity == "" {
				return errors.New("created owned chain not observed")
			}
			a.Rules[key] = "CREATED"
			a.Rules[fmt.Sprintf("own/%d/%s/%s", family, chain.table, chain.name)] = identity
			if err = n.save(ctx, a); err != nil {
				return err
			}
			if _, err = n.tables(ctx, family, "", chain.table, "-A", chain.name, "-j", "DROP"); err != nil {
				return err
			}
		}
		if err := n.replaceForward(ctx, a, family, nil, false); err != nil {
			return err
		}
		if family == 4 || r.Profile == NetworkPublicDual {
			source := r.Source4
			if family == 6 {
				source = r.Source6
			}
			if _, err := n.tables(ctx, family, "", "nat", "-F", nat); err != nil {
				return err
			}
			if _, err := n.tables(ctx, family, "", "nat", "-A", nat, "-m", "comment", "--comment", r.NATGeneration, "-j", "SNAT", "--to-source", source); err != nil {
				return err
			}
		}
		if err := n.verifyRuleSet(ctx, family, "filter", i, [][]string{{"-j", "DROP"}}); err != nil {
			return err
		}
		if family == 4 || r.Profile == NetworkPublicDual {
			source := r.Source4
			if family == 6 {
				source = r.Source6
			}
			if err := n.verifyRuleSet(ctx, family, "nat", nat, [][]string{{"-m", "comment", "--comment", r.NATGeneration, "-j", "SNAT", "--to-source", source}}); err != nil {
				return err
			}
		}
		for _, hook := range networkHooks(r, family) {
			args := append([]string{"-I", hook.chain, "1"}, hook.args...)
			if _, err := n.tables(ctx, family, "", hook.table, args...); err != nil {
				return err
			}
		}
	}
	return n.captureRules(ctx, a)
}
func (n *Network) replaceForward(ctx context.Context, a *networkAllocation, family int, blocked []netip.Prefix, enabled bool) error {
	f, _, _ := networkChains(a.Record)
	if _, err := n.tables(ctx, family, "", "filter", "-F", f); err != nil {
		return err
	}
	rules := networkForwardRules(a.Record, family, blocked, n.cfg.Resolvers, enabled)
	for j, rule := range rules {
		if j == len(rules)-1 {
			rule = append([]string{"-m", "comment", "--comment", a.Record.FilterGeneration}, rule...)
			rules[j] = rule
		}
		args := append([]string{"-A", f}, rule...)
		if _, err := n.tables(ctx, family, "", "filter", args...); err != nil {
			return err
		}
	}
	return n.verifyRuleSet(ctx, family, "filter", f, rules)
}
func (n *Network) captureRules(ctx context.Context, a *networkAllocation) error {
	f, i, nat := networkChains(a.Record)
	for _, family := range []int{4, 6} {
		tables := []string{"filter"}
		if family == 4 || a.Record.Profile == NetworkPublicDual {
			tables = append(tables, "nat")
		}
		for _, table := range tables {
			raw, err := n.tables(ctx, family, "", table, "-S")
			if err != nil {
				return err
			}
			if err = n.provePlacement(raw, a.Record, family, table); err != nil {
				return err
			}
			view, err := networkRuleView(raw, a.Record, family, table)
			if err != nil {
				return err
			}
			a.Rules[fmt.Sprintf("all/%d/%s", family, table)] = view
			for _, chain := range []string{f, i, nat} {
				observed := networkChainInventory(raw, chain)
				if observed != "" {
					a.Rules[fmt.Sprintf("own/%d/%s/%s", family, table, chain)] = observed
				}
			}
		}
	}
	if a.Record.Profile == NetworkPublicV4 {
		raw, err := n.tables(ctx, 6, a.Record.NetnsPath, "filter", "-S")
		if err != nil {
			return err
		}
		a.Rules["peer/6/filter"] = string(raw)
	}
	return nil
}
func (n *Network) provePlacement(raw []byte, r NetworkRecord, family int, table string) error {
	allocations, err := networkAllocations()
	if err != nil {
		return err
	}
	trusted := make(map[string]bool)
	for _, a := range allocations {
		if a.Record.Profile == NetworkNone || a.Record.State == "CLEANED" {
			continue
		}
		for _, h := range networkHooks(a.Record, family) {
			if h.table == table {
				trusted["-A "+h.chain+" "+strings.Join(h.args, " ")] = true
			}
		}
	}
	for _, h := range networkHooks(r, family) {
		if h.table != table {
			continue
		}
		want := "-A " + h.chain + " " + strings.Join(h.args, " ")
		found := false
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			if !strings.HasPrefix(line, "-A "+h.chain+" ") {
				continue
			}
			if line == want {
				found = true
				break
			}
			// Only exact scoped hooks of another durable product allocation may
			// precede ours. A broad foreign ACCEPT/MASQUERADE is never ignored.
			if !trusted[line] {
				return errors.New("owned network hook does not precede foreign authority")
			}
		}
		if !found {
			return errors.New("owned network hook absent from affirmative inventory")
		}
	}
	return nil
}
func (n *Network) verifyRules(ctx context.Context, a *networkAllocation) error {
	for key, expected := range a.Rules {
		if !strings.HasPrefix(key, "all/") && key != "peer/6/filter" {
			continue
		}
		parts := strings.Split(key, "/")
		family := 4
		if parts[1] == "6" {
			family = 6
		}
		ns := ""
		if parts[0] == "peer" {
			ns = a.Record.NetnsPath
		}
		raw, err := n.tables(ctx, family, ns, parts[2], "-S")
		if err != nil {
			return err
		}
		actual := string(raw)
		if ns == "" {
			actual, err = networkRuleView(raw, a.Record, family, parts[2])
			if err != nil {
				return err
			}
		}
		if actual != expected {
			return errors.New("owned firewall or hook inventory drift")
		}
		if ns == "" {
			if err = n.provePlacement(raw, a.Record, family, parts[2]); err != nil {
				return err
			}
		}
	}
	for _, family := range []int{4, 6} {
		if a.Rules[fmt.Sprintf("all/%d/filter", family)] == "" {
			return errors.New("missing durable family filter observation")
		}
	}
	return nil
}
func (n *Network) clearFlows(ctx context.Context, a *networkAllocation) error {
	var errs []error
	for _, ip := range []string{a.Record.PeerIPv4, a.Record.PeerIPv6} {
		if ip == "" {
			continue
		}
		family := "ipv4"
		if strings.Contains(ip, ":") {
			family = "ipv6"
		}
		// Original and reply tuples are queried independently. Never use a broad
		// conntrack flush or the shared SNAT host address as a deletion selector.
		for _, direction := range []string{"--orig-src", "--orig-dst", "--reply-src", "--reply-dst"} {
			key := family + "/" + direction
			a.Flows[key] = "DELETE_SUBMITTED"
			if err := n.save(ctx, a); err != nil {
				return err
			}
			out, status, err := n.networkStatus(ctx, "conntrack", "", []string{"-D", "-f", family, direction, ip})
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if status.Kind != "exit" || status.OOMKilled || (status.Value != 0 && !(status.Value == 1 && strings.Contains(string(out), "0 flow entries"))) {
				errs = append(errs, fmt.Errorf("scoped conntrack deletion failed: %s/%d %.4096s", status.Kind, status.Value, out))
				continue
			}
			a.Flows[key] = fmt.Sprintf("DELETED:%s:exit=%d", networkDigest(out), status.Value)
			if err = n.save(ctx, a); err != nil {
				return err
			}
		}
	}
	return errors.Join(append(errs, n.verifyFlowsAbsent(ctx, a))...)
}
func (n *Network) verifyFlowsAbsent(ctx context.Context, a *networkAllocation) error {
	for _, ip := range []string{a.Record.PeerIPv4, a.Record.PeerIPv6} {
		if ip == "" {
			continue
		}
		family := "ipv4"
		if strings.Contains(ip, ":") {
			family = "ipv6"
		}
		for _, direction := range []string{"--orig-src", "--orig-dst", "--reply-src", "--reply-dst"} {
			out, status, err := n.networkStatus(ctx, "conntrack", "", []string{"-L", "-f", family, direction, ip, "-o", "extended"})
			if err != nil {
				return err
			}
			if status.Kind != "exit" || status.OOMKilled || status.Value != 0 {
				return fmt.Errorf("scoped conntrack inventory failed: %s/%d", status.Kind, status.Value)
			}
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				if line != "" && !strings.HasPrefix(line, "conntrack ") && !strings.Contains(line, "0 flow entries") {
					return errors.New("instance conntrack flows remain")
				}
			}
			a.Flows[family+"/"+direction] = "ABSENT:" + string(out)
		}
	}
	return nil
}
func (n *Network) removeFirewall(ctx context.Context, a *networkAllocation) error {
	r := a.Record
	f, i, nat := networkChains(r)
	for _, family := range []int{4, 6} {
		tables := []string{"filter"}
		if family == 4 || r.Profile == NetworkPublicDual {
			tables = append(tables, "nat")
		}
		for _, table := range tables {
			raw, err := n.tables(ctx, family, "", table, "-S")
			if err != nil {
				return err
			}
			for _, chain := range []string{f, i, nat} {
				actual := networkChainInventory(raw, chain)
				if actual == "" {
					continue
				}
				if a.Rules[fmt.Sprintf("intent/%d/%s/%s", family, table, chain)] != "CREATED" {
					return ErrCreateUnresolved
				}
				if a.Rules[fmt.Sprintf("own/%d/%s/%s", family, table, chain)] == "" {
					return errors.New("owned chain creation observation missing; retaining network allocation")
				}
			}
			for _, h := range networkHooks(r, family) {
				if h.table != table {
					continue
				}
				expected := "-A " + h.chain + " " + strings.Join(h.args, " ")
				if slices.Contains(strings.Split(strings.TrimSpace(string(raw)), "\n"), expected) {
					if _, err = n.tables(ctx, family, "", table, append([]string{"-D", h.chain}, h.args...)...); err != nil {
						return err
					}
				}
			}
			for _, chain := range []string{f, i, nat} {
				if networkChainInventory(raw, chain) == "" {
					continue
				}
				if _, err = n.tables(ctx, family, "", table, "-F", chain); err != nil {
					return err
				}
				if _, err = n.tables(ctx, family, "", table, "-X", chain); err != nil {
					return err
				}
			}
			raw, err = n.tables(ctx, family, "", table, "-S")
			if err != nil {
				return err
			}
			for _, chain := range []string{f, i, nat} {
				if strings.Contains(string(raw), chain) {
					return errors.New("owned firewall/NAT references remain")
				}
			}
		}
	}
	return nil
}
func networkRuleView(raw []byte, r NetworkRecord, family int, table string) (string, error) {
	allocations, err := networkAllocations()
	if err != nil {
		return "", err
	}
	ignoredChains := make(map[string]bool)
	ignoredHooks := make(map[string]bool)
	for _, a := range allocations {
		if a.Record.Generation == r.Generation || a.Record.Profile == NetworkNone || a.Record.State == "CLEANED" {
			continue
		}
		f, i, nat := networkChains(a.Record)
		for _, chain := range []string{f, i, nat} {
			ignoredChains[chain] = true
		}
		for _, h := range networkHooks(a.Record, family) {
			if h.table == table {
				ignoredHooks["-A "+h.chain+" "+strings.Join(h.args, " ")] = true
			}
		}
	}
	var out []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		fields := strings.Fields(line)
		if ignoredHooks[line] || len(fields) > 1 && ignoredChains[fields[1]] && (fields[0] == "-A" || fields[0] == "-N") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n"), nil
}
func (n *Network) revokeForCleanup(ctx context.Context, a *networkAllocation) error {
	if err := n.verifyLink(ctx, a); err != nil {
		return err
	}
	if _, err := n.ip(ctx, "", "link", "set", a.Record.HostInterface, "down"); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	f, _, _ := networkChains(a.Record)
	for _, family := range []int{4, 6} {
		raw, err := n.tables(ctx, family, "", "filter", "-S")
		if err != nil {
			return err
		}
		if networkChainInventory(raw, f) == "" {
			continue
		}
		if a.Rules[fmt.Sprintf("intent/%d/filter/%s", family, f)] != "CREATED" {
			return ErrCreateUnresolved
		}
		if err = n.replaceForward(ctx, a, family, nil, false); err != nil {
			return errors.Join(err, n.emergencyClose(ctx, a))
		}
		observed, err := n.tables(ctx, family, "", "filter", "-S")
		if err != nil {
			return err
		}
		a.Rules[fmt.Sprintf("own/%d/filter/%s", family, f)] = networkChainInventory(observed, f)
	}
	if err := n.clearFlows(ctx, a); err != nil {
		return errors.Join(err, n.emergencyClose(ctx, a))
	}
	a.Record.State = "CLOSED"
	return n.save(ctx, a)
}
func (n *Network) verifyRuleSet(ctx context.Context, family int, table, chain string, rules [][]string) error {
	raw, err := n.tables(ctx, family, "", table, "-S", chain)
	if err != nil {
		return err
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, "-A "+chain+" ") {
			count++
		}
	}
	if count != len(rules) {
		return errors.New("owned chain has missing or unexpected policy rules")
	}
	for _, rule := range rules {
		if _, err = n.tables(ctx, family, "", table, append([]string{"-C", chain}, rule...)...); err != nil {
			return errors.Join(errors.New("effective owned policy does not match approved rules"), err)
		}
	}
	return nil
}
