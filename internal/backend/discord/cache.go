package discordbackend

import "github.com/bwmarrin/discordgo"

// SDK State getters return cache-owned pointers. Copy only the fields actually
// used while holding State's lock; no cache pointer survives a remote lookup.
type channelFacts struct {
	ID, GuildID, ParentID string
	Type                  discordgo.ChannelType
}

func (b *Backend) channelFacts(id string) (channelFacts, bool) {
	s := b.session.State
	if s == nil {
		return channelFacts{}, false
	}
	c, e := s.Channel(id)
	if e != nil || c == nil {
		return channelFacts{}, false
	}
	s.RLock()
	result := channelFacts{c.ID, c.GuildID, c.ParentID, c.Type}
	s.RUnlock()
	return result, true
}
func (b *Backend) channelSnapshot(id string) (*discordgo.Channel, bool) {
	s := b.session.State
	if s == nil {
		return nil, false
	}
	c, e := s.Channel(id)
	if e != nil || c == nil {
		return nil, false
	}
	s.RLock()
	out := &discordgo.Channel{ID: c.ID, GuildID: c.GuildID, Type: c.Type, ParentID: c.ParentID}
	if c.PermissionOverwrites != nil {
		out.PermissionOverwrites = make([]*discordgo.PermissionOverwrite, len(c.PermissionOverwrites))
		for n, o := range c.PermissionOverwrites {
			if o != nil {
				copy := *o
				out.PermissionOverwrites[n] = &copy
			}
		}
	}
	s.RUnlock()
	return out, true
}
func (b *Backend) guildSnapshot(id string) (*discordgo.Guild, bool) {
	s := b.session.State
	if s == nil {
		return nil, false
	}
	g, e := s.Guild(id)
	if e != nil || g == nil {
		return nil, false
	}
	s.RLock()
	out := &discordgo.Guild{ID: g.ID, OwnerID: g.OwnerID}
	if g.Roles != nil {
		out.Roles = make([]*discordgo.Role, len(g.Roles))
		for n, r := range g.Roles {
			if r != nil {
				out.Roles[n] = &discordgo.Role{ID: r.ID, Permissions: r.Permissions}
			}
		}
	}
	s.RUnlock()
	return out, true
}
func (b *Backend) memberSnapshot(guild, user string) (*discordgo.Member, bool) {
	s := b.session.State
	if s == nil {
		return nil, false
	}
	m, e := s.Member(guild, user)
	if e != nil || m == nil {
		return nil, false
	}
	s.RLock()
	if m.User == nil || m.User.ID != user {
		s.RUnlock()
		return nil, false
	}
	out := &discordgo.Member{GuildID: m.GuildID, User: &discordgo.User{ID: m.User.ID}, Roles: append([]string(nil), m.Roles...)}
	s.RUnlock()
	return out, true
}
