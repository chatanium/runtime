package discordbackend

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"sync"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/discord-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"
	_ "modernc.org/sqlite"
)

type ownershipStore struct {
	db            *sql.DB
	config        Config
	commands      chan struct{}
	mu            sync.Mutex
	routeReaders  map[RouteKey]int
	routeDeleting map[RouteKey]bool
	changed       chan struct{}
}

func openOwnership(path string, c Config) (*ownershipStore, error) {
	directory, e := os.Lstat(c.OwnershipDirectory)
	if e != nil || !directory.IsDir() || directory.Mode().Perm() != 0700 {
		return nil, unavailable("DISCORD_OWNERSHIP_DIRECTORY_INVALID")
	}
	db, e := sql.Open("sqlite", path)
	if e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_OPEN_FAILED")
	}
	db.SetMaxOpenConns(1)
	for _, q := range []string{"PRAGMA journal_mode=WAL", "PRAGMA synchronous=FULL", "PRAGMA foreign_keys=ON", `CREATE TABLE IF NOT EXISTS commands(application TEXT NOT NULL,guild TEXT NOT NULL,type INTEGER NOT NULL,name TEXT NOT NULL,command_id TEXT NOT NULL DEFAULT '',module TEXT NOT NULL,state TEXT NOT NULL,PRIMARY KEY(application,guild,type,name))`, `CREATE INDEX IF NOT EXISTS command_id_idx ON commands(application,command_id)`, `CREATE TABLE IF NOT EXISTS routes(application TEXT NOT NULL,kind INTEGER NOT NULL,custom_id TEXT NOT NULL,module TEXT NOT NULL,PRIMARY KEY(application,kind,custom_id))`} {
		if _, e = db.Exec(q); e != nil {
			db.Close()
			return nil, unavailable("DISCORD_OWNERSHIP_OPEN_FAILED")
		}
	}
	if e = os.Chmod(path, 0600); e != nil {
		db.Close()
		return nil, unavailable("DISCORD_OWNERSHIP_OPEN_FAILED")
	}
	return &ownershipStore{db: db, config: c, commands: make(chan struct{}, 1), routeReaders: make(map[RouteKey]int), routeDeleting: make(map[RouteKey]bool), changed: make(chan struct{})}, nil
}
func (s *ownershipStore) Close() error {
	if e := s.db.Close(); e != nil {
		return unavailable("DISCORD_OWNERSHIP_CLOSE_FAILED")
	}
	return nil
}
func (s *ownershipStore) notify() { close(s.changed); s.changed = make(chan struct{}) }
func routeClaims(claims []*wire.InteractionRouteClaim, app string) ([]RouteKey, error) {
	keys := make([]RouteKey, 0, len(claims))
	seen := map[RouteKey]bool{}
	for _, c := range claims {
		if c == nil || c.ApplicationId != app || (c.InteractionKind != wire.InteractionRouteKind_INTERACTION_ROUTE_KIND_MESSAGE_COMPONENT && c.InteractionKind != wire.InteractionRouteKind_INTERACTION_ROUTE_KIND_MODAL_SUBMIT) || c.CustomId == "" || len([]rune(c.CustomId)) > 100 {
			return nil, invalid("INTERACTION_ROUTE_INVALID")
		}
		key := RouteKey{c.ApplicationId, int32(c.InteractionKind), c.CustomId}
		if seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	return keys, nil
}
func (h *Helper) registerRoutes(ctx context.Context, request proto.Message) (proto.Message, error) {
	req, ok := request.(*wire.RegisterInteractionRoutesRequest)
	if !ok {
		return nil, invalid("INTERACTION_ROUTE_INVALID")
	}
	keys, e := routeClaims(req.Claims, h.backend.config.ApplicationID)
	if e != nil {
		return nil, e
	}
	return h.changeRoutes(ctx, "RegisterInteractionRoutes", keys, false)
}
func (h *Helper) unregisterRoutes(ctx context.Context, request proto.Message) (proto.Message, error) {
	req, ok := request.(*wire.UnregisterInteractionRoutesRequest)
	if !ok {
		return nil, invalid("INTERACTION_ROUTE_INVALID")
	}
	keys, e := routeClaims(req.Claims, h.backend.config.ApplicationID)
	if e != nil {
		return nil, e
	}
	return h.changeRoutes(ctx, "UnregisterInteractionRoutes", keys, true)
}
func (h *Helper) changeRoutes(ctx context.Context, operation string, keys []RouteKey, remove bool) (proto.Message, error) {
	if len(keys) > h.backend.config.MaxRoutesPerRequest {
		return nil, status.Error(codes.ResourceExhausted, "INTERACTION_ROUTE_QUOTA_EXCEEDED")
	}
	op, e := h.authorize(ctx, operation, &RESTPlan{Targets: []ResourceTarget{{Kind: "application_id", ID: h.backend.config.ApplicationID}}})
	if e != nil {
		return nil, e
	}
	defer op.Admission.Release()
	ctx, done, e := h.gatewayContext(op.Context, op.Principal)
	if e != nil {
		return nil, e
	}
	defer done()
	s := h.backend.ownership
	s.mu.Lock()
	defer s.mu.Unlock()
	// Deletion marks block both new outbound sends and new event credentials.
	for _, key := range keys {
		if s.routeDeleting[key] {
			return nil, unavailable("INTERACTION_ROUTE_BEING_REMOVED")
		}
		var owner string
		e := s.db.QueryRowContext(ctx, "SELECT module FROM routes WHERE application=? AND kind=? AND custom_id=?", key.ApplicationID, key.Kind, key.CustomID).Scan(&owner)
		if e != nil && e != sql.ErrNoRows {
			return nil, unavailable("DISCORD_OWNERSHIP_READ_FAILED")
		}
		if e == nil && owner != string(op.Principal.ModuleID) {
			return nil, denied("INTERACTION_ROUTE_OWNERSHIP_CONFLICT")
		}
	}
	if remove {
		for _, key := range keys {
			s.routeDeleting[key] = true
		}
		defer func() {
			for _, key := range keys {
				delete(s.routeDeleting, key)
			}
			s.notify()
		}()
		for {
			busy := false
			for _, key := range keys {
				busy = busy || s.routeReaders[key] != 0
			}
			if !busy {
				break
			}
			changed := s.changed
			s.mu.Unlock()
			select {
			case <-ctx.Done():
				s.mu.Lock()
				return nil, ctx.Err()
			case <-changed:
			}
			s.mu.Lock()
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	defer tx.Rollback()
	var total, owned int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM routes").Scan(&total); e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_READ_FAILED")
	}
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM routes WHERE module=?", string(op.Principal.ModuleID)).Scan(&owned); e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_READ_FAILED")
	}
	added := 0
	for _, key := range keys {
		var owner string
		e = tx.QueryRowContext(ctx, "SELECT module FROM routes WHERE application=? AND kind=? AND custom_id=?", key.ApplicationID, key.Kind, key.CustomID).Scan(&owner)
		if e != nil && e != sql.ErrNoRows {
			return nil, unavailable("DISCORD_OWNERSHIP_READ_FAILED")
		}
		if e == nil && owner != string(op.Principal.ModuleID) {
			return nil, denied("INTERACTION_ROUTE_OWNERSHIP_CONFLICT")
		}
		if remove {
			if _, e = tx.ExecContext(ctx, "DELETE FROM routes WHERE application=? AND kind=? AND custom_id=? AND module=?", key.ApplicationID, key.Kind, key.CustomID, string(op.Principal.ModuleID)); e != nil {
				return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
			}
		} else if e == sql.ErrNoRows {
			added++
			if total+added > s.config.RoutesPerHost || owned+added > s.config.RoutesPerModule {
				return nil, status.Error(codes.ResourceExhausted, "INTERACTION_ROUTE_QUOTA_EXCEEDED")
			}
			if _, e = tx.ExecContext(ctx, "INSERT INTO routes VALUES(?,?,?,?)", key.ApplicationID, key.Kind, key.CustomID, string(op.Principal.ModuleID)); e != nil {
				return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
			}
		}
	}
	if e = tx.Commit(); e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	return &emptypb.Empty{}, nil
}
func (s *ownershipStore) routeOwner(ctx context.Context, key RouteKey) (runtime.ModuleID, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.routeDeleting[key] {
		return "", denied("INTERACTION_ROUTE_NOT_OWNED")
	}
	var owner string
	if e := s.db.QueryRowContext(ctx, "SELECT module FROM routes WHERE application=? AND kind=? AND custom_id=?", key.ApplicationID, key.Kind, key.CustomID).Scan(&owner); e != nil {
		return "", denied("INTERACTION_ROUTE_NOT_OWNED")
	}
	return runtime.ModuleID(owner), nil
}
func (s *ownershipStore) leaseRoutes(ctx context.Context, owner runtime.ModuleID, keys []RouteKey) (func(), error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range keys {
		if s.routeDeleting[key] {
			return nil, denied("INTERACTION_ROUTE_NOT_OWNED")
		}
		var actual string
		if e := s.db.QueryRowContext(ctx, "SELECT module FROM routes WHERE application=? AND kind=? AND custom_id=?", key.ApplicationID, key.Kind, key.CustomID).Scan(&actual); e != nil || actual != string(owner) {
			return nil, denied("INTERACTION_ROUTE_NOT_OWNED")
		}
	}
	for _, key := range keys {
		s.routeReaders[key]++
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			s.mu.Lock()
			for _, key := range keys {
				s.routeReaders[key]--
				if s.routeReaders[key] == 0 {
					delete(s.routeReaders, key)
				}
			}
			s.notify()
			s.mu.Unlock()
		})
	}, nil
}
func (s *ownershipStore) commandOwner(ctx context.Context, app, id string) (runtime.ModuleID, error) {
	var owner string
	if e := s.db.QueryRowContext(ctx, "SELECT module FROM commands WHERE application=? AND command_id=? LIMIT 1", app, id).Scan(&owner); e != nil {
		return "", denied("COMMAND_NOT_OWNED")
	}
	return runtime.ModuleID(owner), nil
}

type commandRow struct {
	key              CommandKey
	id, owner, state string
}
type commandClaim struct {
	store    *ownershipStore
	mutation *CommandMutation
	owner    runtime.ModuleID
	before   []commandRow
}

func (s *ownershipStore) rows(ctx context.Context, app, guild string) ([]commandRow, error) {
	r, e := s.db.QueryContext(ctx, "SELECT type,name,command_id,module,state FROM commands WHERE application=? AND guild=?", app, guild)
	if e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_READ_FAILED")
	}
	defer r.Close()
	var out []commandRow
	for r.Next() {
		var v commandRow
		if r.Scan(&v.key.Type, &v.key.Name, &v.id, &v.owner, &v.state) != nil {
			return nil, unavailable("DISCORD_OWNERSHIP_READ_FAILED")
		}
		out = append(out, v)
	}
	return out, r.Err()
}
func (b *Backend) beginCommand(ctx context.Context, p runtime.InstancePrincipal, m *CommandMutation) (*commandClaim, error) {
	s := b.ownership
	select {
	case s.commands <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	failed := true
	defer func() {
		if failed {
			<-s.commands
		}
	}()
	if m.ApplicationID != b.config.ApplicationID || (m.GuildID != "" && !snowflake(m.GuildID)) {
		return nil, denied("COMMAND_OWNERSHIP_CONFLICT")
	}
	before, e := s.rows(ctx, m.ApplicationID, m.GuildID)
	if e != nil {
		return nil, e
	}
	path := "/applications/" + m.ApplicationID
	if m.GuildID != "" {
		path += "/guilds/" + m.GuildID
	}
	var remote []struct {
		ID   string `json:"id"`
		Type int32  `json:"type"`
		Name string `json:"name"`
	}
	if e = b.readJSON(ctx, p, path+"/commands", &remote); e != nil {
		return nil, e
	}
	// Editing a description need not repeat the existing immutable key fields.
	if m.CommandID != "" {
		for _, r := range before {
			if r.id == m.CommandID && r.owner == string(p.ModuleID) {
				for n := range m.Commands {
					if m.Commands[n].Name == "" {
						m.Commands[n].Name = r.key.Name
					}
					if m.Commands[n].Type == 0 {
						m.Commands[n].Type = r.key.Type
					}
				}
				break
			}
		}
	}
	for _, r := range before {
		affected := m.Bulk || (m.CommandID != "" && r.id == m.CommandID)
		for _, key := range m.Commands {
			affected = affected || r.key == key
		}
		if affected && r.state == "UNKNOWN" {
			return nil, unavailable("COMMAND_OUTCOME_UNKNOWN")
		}
	}
	seen := make(map[CommandKey]bool, len(m.Commands))
	for _, key := range m.Commands {
		if seen[key] {
			return nil, invalid("COMMAND_KEY_DUPLICATE")
		}
		seen[key] = true
	}
	ownedID := false
	for _, r := range before {
		if r.id == m.CommandID && r.owner == string(p.ModuleID) && m.CommandID != "" {
			ownedID = true
		}
		if m.Bulk && r.owner != string(p.ModuleID) {
			return nil, denied("COMMAND_NAMESPACE_NOT_EXCLUSIVE")
		}
		for _, key := range m.Commands {
			if r.key == key && r.owner != string(p.ModuleID) {
				return nil, denied("COMMAND_OWNERSHIP_CONFLICT")
			}
		}
	}
	if m.CommandID != "" && !ownedID {
		return nil, denied("COMMAND_NOT_OWNED")
	}
	for _, r := range remote {
		owner := ""
		for _, v := range before {
			if v.id == r.ID {
				owner = v.owner
				break
			}
		}
		if m.Bulk && owner != string(p.ModuleID) {
			return nil, denied("COMMAND_NAMESPACE_NOT_EXCLUSIVE")
		}
		for _, key := range m.Commands {
			kind := r.Type
			if kind == 0 {
				kind = 1
			}
			if key.Type == kind && key.Name == r.Name && owner != string(p.ModuleID) {
				return nil, denied("COMMAND_OWNERSHIP_CONFLICT")
			}
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	defer tx.Rollback()
	for _, key := range m.Commands {
		if key.Type < 1 || key.Type > 3 || key.Name == "" {
			return nil, invalid("COMMAND_KEY_INVALID")
		}
		if _, e = tx.ExecContext(ctx, `INSERT INTO commands VALUES(?,?,?,?,?,?,?) ON CONFLICT(application,guild,type,name) DO UPDATE SET state='UNKNOWN'`, m.ApplicationID, m.GuildID, key.Type, key.Name, m.CommandID, string(p.ModuleID), "UNKNOWN"); e != nil {
			return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
		}
	}
	if m.Bulk {
		_, e = tx.ExecContext(ctx, "UPDATE commands SET state='UNKNOWN' WHERE application=? AND guild=? AND module=?", m.ApplicationID, m.GuildID, string(p.ModuleID))
	} else if m.Delete {
		_, e = tx.ExecContext(ctx, "UPDATE commands SET state='UNKNOWN' WHERE application=? AND guild=? AND command_id=? AND module=?", m.ApplicationID, m.GuildID, m.CommandID, string(p.ModuleID))
	}
	if e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	if e = tx.Commit(); e != nil {
		return nil, unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	failed = false
	return &commandClaim{s, m, p.ModuleID, before}, nil
}

type commandSnapshot struct {
	ID            string `json:"id"`
	Type          int32  `json:"type"`
	Name          string `json:"name"`
	ApplicationID string `json:"application_id"`
	GuildID       string `json:"guild_id"`
}

func (c *commandClaim) finish(ctx context.Context, dispatched, success bool, body []byte) error {
	defer func() { <-c.store.commands }()
	if !success && dispatched {
		return nil
	}
	m, s := c.mutation, c.store
	var values []commandSnapshot
	if success && !m.Delete {
		if m.Bulk {
			if json.Unmarshal(body, &values) != nil {
				return unavailable("DISCORD_COMMAND_RESULT_INVALID")
			}
		} else {
			var value commandSnapshot
			if json.Unmarshal(body, &value) != nil {
				return unavailable("DISCORD_COMMAND_RESULT_INVALID")
			}
			values = append(values, value)
		}
		if len(values) != len(m.Commands) {
			return unavailable("DISCORD_COMMAND_RESULT_INVALID")
		}
		seen := map[CommandKey]bool{}
		for _, value := range values {
			key := CommandKey{value.Type, value.Name}
			expected := false
			for _, wanted := range m.Commands {
				expected = expected || wanted == key
			}
			if !snowflake(value.ID) || value.ApplicationID != m.ApplicationID || value.GuildID != m.GuildID || !expected || seen[key] {
				return unavailable("DISCORD_COMMAND_RESULT_INVALID")
			}
			seen[key] = true
		}
	}
	tx, e := s.db.BeginTx(ctx, nil)
	if e != nil {
		return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	defer tx.Rollback()
	if !success {
		if _, e = tx.ExecContext(ctx, "DELETE FROM commands WHERE application=? AND guild=?", m.ApplicationID, m.GuildID); e != nil {
			return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
		}
		for _, r := range c.before {
			if _, e = tx.ExecContext(ctx, "INSERT INTO commands VALUES(?,?,?,?,?,?,?)", m.ApplicationID, m.GuildID, r.key.Type, r.key.Name, r.id, r.owner, r.state); e != nil {
				return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
			}
		}
	} else if m.Delete {
		_, e = tx.ExecContext(ctx, "DELETE FROM commands WHERE application=? AND guild=? AND command_id=? AND module=?", m.ApplicationID, m.GuildID, m.CommandID, string(c.owner))
	} else {
		if m.Bulk {
			_, e = tx.ExecContext(ctx, "DELETE FROM commands WHERE application=? AND guild=? AND module=?", m.ApplicationID, m.GuildID, string(c.owner))
		} else if m.CommandID != "" {
			_, e = tx.ExecContext(ctx, "DELETE FROM commands WHERE application=? AND guild=? AND command_id=? AND module=?", m.ApplicationID, m.GuildID, m.CommandID, string(c.owner))
		}
		if e != nil {
			return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
		}
		for _, value := range values {
			if _, e = tx.ExecContext(ctx, `INSERT INTO commands VALUES(?,?,?,?,?,?,?) ON CONFLICT(application,guild,type,name) DO UPDATE SET command_id=excluded.command_id,state=excluded.state`, m.ApplicationID, m.GuildID, value.Type, value.Name, value.ID, string(c.owner), "CONFIRMED"); e != nil {
				return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
			}
		}
	}
	if e != nil {
		return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	if e = tx.Commit(); e != nil {
		return unavailable("DISCORD_OWNERSHIP_WRITE_FAILED")
	}
	return nil
}
