package Slash

import (
	"strings"

	"github.com/bwmarrin/discordgo"
	"github.com/thirdscam/chatanium/src/Util/Log"
)

// Handle for slash commands when user input
func (t *CommandManager) HandleCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	// 1. Retrieve command name from interaction (input from user)
	cmdName := ""
	switch i.Type {
	case discordgo.InteractionApplicationCommand:
		Log.Verbose.Printf("G:%s > Application command data: %+v", i.GuildID, i.ApplicationCommandData())
		cmdName = i.ApplicationCommandData().Name
	case discordgo.InteractionModalSubmit:
		Log.Verbose.Printf("G:%s > Modal submit data: %+v", i.GuildID, i.ModalSubmitData())
		// InteractionModalSubmit not have command name, so we need to extract it from custom ID
		customID := i.ModalSubmitData().CustomID

		// Extract command name from custom ID (e.g "draw/req_xxx" -> "draw")
		safeCmdName := ""
		if idx := strings.Index(customID, "/"); idx > 0 {
			safeCmdName = customID[:idx]
		} else if idx == -1 {
			// if "/" is not found, use entire custom ID
			safeCmdName = cmdName
		}

		// only allow alphabet, number, and underscore (for security)
		for _, r := range safeCmdName {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
				cmdName += string(r)
			}
		}

		Log.Verbose.Printf("G:%s > Extracted CmdName from customID (%s -> %s)", i.GuildID, customID, safeCmdName)
	}

	if cmdName == "" {
		Log.Warn.Printf("[Unsupport] G:%s > Cannot extract command name from interaction. Please check related interaction.", i.GuildID)
		Log.Verbose.Printf("G:%s > Interaction ignored", i.GuildID)
		return
	}

	// 2. search command name from registered commands
	//    if command name is not found, ignore this event
	for schema, handle := range t.Commands {
		if schema.Name == cmdName { // schema.Name is command name
			handle(s, i) // call handler
			return
		}
	}

	Log.Warn.Printf("[Integrity] G:%s > Cannot find command name from interaction.", i.GuildID)
}

// Manage and store CommandManager for each guild.
type Guild struct {
	// Discord session from discordgo
	Client *discordgo.Session
	// Store each CommandManager of guild
	cmdMgrs []CommandManager
}

// Start slash command interface.
func (t *Guild) Start() {
	// Add handler for slash command event (InteractionCreate)
	t.Client.AddHandler(func(s *discordgo.Session, i *discordgo.InteractionCreate) {
		// 1. Get guild ID from interaction
		guildId := i.GuildID
		isFindCmdMgr := false

		// 2. Search CommandManager for guild
		for _, v := range t.cmdMgrs {
			if v.GuildID == guildId {
				// 2-1. Execute command: but if command is not found, ignore this event
				isFindCmdMgr = true
				v.HandleCommand(s, i)
				break
			}
		}

		if !isFindCmdMgr {
			Log.Warn.Printf("[Integrity] G:%s > Cannot find CommandManager for this guild. Please check this guild.", guildId)
		}
	})
}

// Register slash commands to guild.
// This function used on guild create event.
func (t *Guild) OnGuildCreated(id string) {
	// TODO(Feature): ACL of slash commands for each guild

	// 1. Make CommandManager for guild
	cmdMgrs := CommandManager{
		Client:   t.Client,
		Commands: getCommands(id),
		GuildID:  id,
	}

	// 2. Start CommandManager
	cmdMgrs.Start()
	cmdMgrs.Vaildate() // Validate commands

	// 3. Append to CommandManager storage
	t.cmdMgrs = append(t.cmdMgrs, cmdMgrs)
}

// Remove slash commands from guild.
// This function used on guild delete event.
func (t *Guild) OnGuildDeleted(id string) {
	for i, v := range t.cmdMgrs {
		if v.GuildID == id {
			// FIXME(Performance): remove CommandManager for lefted guild nevertheless handler goroutine is may running,
			// so this goroutine maybe not stopped. The current way to fix this is to periodically restart
			// the server to remove handlers for guilds that have lefted.
			t.cmdMgrs = append(t.cmdMgrs[:i], t.cmdMgrs[i+1:]...)
			break
		}
	}
}
