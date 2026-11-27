package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/x/term"
	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/portable/install"
	"github.com/thirdscam/chatanium/internal/portable/process"
)

var moduleCommand = &cobra.Command{Use: "module", Short: "Manage runtime modules"}

func init() {
	moduleCommand.AddCommand(moduleInstallCommand())
	addOperatorCommands("modules", moduleCommand)
}

func moduleInstallCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "install <oci-archive>",
		Short: "Review and install one local OCI module without starting it",
		Args:  cobra.ExactArgs(1),
	}
	cmd.SetFlagErrorFunc(legacyFlagError)
	flags := cmd.Flags()
	var moduleOptions install.GenerateOptions
	var configFile, grantFile string
	flags.StringVar(&moduleOptions.ModuleID, "module-id", "", "stable module ID (defaults to the verified declaration name)")
	flags.Uint32Var(&moduleOptions.UID, "uid", 1000, "approved nonroot guest UID")
	flags.Uint32Var(&moduleOptions.GID, "gid", 1000, "approved nonroot guest GID")
	flags.StringVar(&configFile, "module-config", "", "canonical absolute module configuration JSON path")
	flags.StringVar(&grantFile, "approval", "", "canonical absolute proposed core-v2 grants JSON path")
	budget := flags.Int64("budget-bytes", install.DefaultBudgetBytes, "maximum installation-owned bytes on first setup")
	limitsFile := flags.String("limits-file", "", "complete portable preparation limits JSON")
	var discord moduleDiscordInput
	flags.StringVar(&discord.guild, "discord-guild-id", "", "Discord starter's only approved guild")
	flags.StringVar(&discord.channel, "discord-channel-id", "", "Discord starter's only approved channel")
	flags.StringVar(&discord.application, "discord-application-id", "", "application ID for a new host Discord backend")
	flags.StringVar(&discord.bot, "discord-bot-user-id", "", "bot user ID for a new host Discord backend")
	flags.StringVar(&discord.tokenFile, "discord-token-file", "", "owner-only file containing the new host Discord bot token")
	approvalFlag(cmd)
	jsonOutputFlag(cmd)
	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		module := moduleOptions
		if configFile != "" {
			data, err := install.ReadInput(configFile)
			if err != nil {
				return err
			}
			if len(data) == 0 {
				return errors.New("module configuration file is empty")
			}
			module.ModuleConfig = data
		}
		if grantFile != "" {
			data, err := install.ReadInput(grantFile)
			if err != nil {
				return err
			}
			if len(data) == 0 {
				return errors.New("module grants file is empty")
			}
			module.Grant = data
		}
		limits := install.DefaultPreparationLimits()
		if *limitsFile != "" {
			var err error
			limits, err = readPreparationLimits(*limitsFile)
			if err != nil {
				return err
			}
		}
		view := commandView(cmd, cmd.ErrOrStderr())
		input := approvalInput(cmd)
		stdin, _ := cmd.InOrStdin().(*os.File)
		jsonOutput, _ := cmd.Flags().GetBool("json")
		jsonApprovals, _ := cmd.Flags().GetBool("json-approvals")
		interactive := view.terminal && stdin != nil && term.IsTerminal(stdin.Fd()) && !jsonOutput && !jsonApprovals && !cmd.Flags().Changed("approve")
		confirm := digestApproval(cmd, input)
		if interactive {
			if err := view.log(logInfo, fmt.Sprintf("Inspecting local archive %q in an isolated guest.", filepath.Base(args[0]))); err != nil {
				return err
			}
			confirm = func(_ string, plan any, _ string) error {
				summary, err := install.DescribeSetupApproval(plan)
				if err != nil {
					return err
				}
				question := "Install this module?"
				if summary.Heading == "Set up Chatanium runtime" {
					question = "Set up Chatanium without starting it?"
					summary.Lines[len(summary.Lines)-1] = "The module is reviewed separately before installation."
				}
				yes, err := promptSetupApproval(view, logInfo, input, summary, question)
				if err == nil && !yes {
					return errSetupDeclined
				}
				return err
			}
		}
		m, err := install.InstallModule(cmd.Context(), install.ModuleInstallOptions{
			Archive: args[0], BudgetBytes: *budget, Limits: limits, Module: module,
			Settings: func(info install.ModuleInstallInfo) (install.ModuleInstallSettings, error) {
				return discord.settings(info, view, input, stdin, interactive)
			},
		}, confirm)
		if errors.Is(err, errSetupDeclined) {
			return view.log(logInfo, "Module install canceled.")
		}
		if errors.Is(err, process.ErrOwnerBusy) {
			return fmt.Errorf("runtime is busy; run chatanium stop before installing: %w", err)
		}
		if err != nil {
			return err
		}
		if out, human := operatorOutput(cmd); human {
			return out.log(logInfo, fmt.Sprintf("Installed module %q. Run chatanium serve to start it.", m.Modules[len(m.Modules)-1].ID))
		}
		return manifestResult(cmd, m, nil)
	}
	return cmd
}

type moduleDiscordInput struct {
	guild, channel, application, bot, tokenFile string
}

func (d moduleDiscordInput) settings(info install.ModuleInstallInfo, view terminalView, input *bufio.Reader, stdin *os.File, interactive bool) (install.ModuleInstallSettings, error) {
	if !info.DiscordStarter {
		if d != (moduleDiscordInput{}) {
			return install.ModuleInstallSettings{}, errors.New("Discord setup flags are only for images declaring the Discord starter capabilities")
		}
		return install.ModuleInstallSettings{}, nil
	}
	if info.Discord != nil && (d.application != "" || d.bot != "" || d.tokenFile != "") {
		return install.ModuleInstallSettings{}, errors.New("Discord backend is already configured; install will not replace its credentials or settings")
	}
	if interactive {
		if err := view.log(logInfo, fmt.Sprintf("Configure Discord for %q (%s).", info.Declaration.Name, info.Declaration.Version)); err != nil {
			return install.ModuleInstallSettings{}, err
		}
		if info.Discord == nil {
			if err := view.indented("Enable GUILDS, GUILD_MESSAGES and the privileged MESSAGE_CONTENT intent for this bot."); err != nil {
				return install.ModuleInstallSettings{}, err
			}
		}
	}
	ask := func(value, label, flag string) (string, error) {
		if value != "" {
			return value, nil
		}
		if !interactive {
			return "", fmt.Errorf("Discord setup requires --%s outside an interactive terminal", flag)
		}
		if _, err := fmt.Fprintf(view.out, "      %s: ", label); err != nil {
			return "", err
		}
		line, err := input.ReadSlice('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return "", err
		}
		value = strings.TrimSpace(string(line))
		if value == "" {
			return "", fmt.Errorf("%s is required", label)
		}
		return value, nil
	}
	guild, err := ask(d.guild, "Guild ID", "discord-guild-id")
	if err != nil {
		return install.ModuleInstallSettings{}, err
	}
	channel, err := ask(d.channel, "Channel ID", "discord-channel-id")
	if err != nil {
		return install.ModuleInstallSettings{}, err
	}
	settings := install.ModuleInstallSettings{GuildID: guild, ChannelID: channel}
	if info.Discord != nil {
		return settings, nil
	}
	application, err := ask(d.application, "Application ID", "discord-application-id")
	if err != nil {
		return install.ModuleInstallSettings{}, err
	}
	bot, err := ask(d.bot, "Bot user ID", "discord-bot-user-id")
	if err != nil {
		return install.ModuleInstallSettings{}, err
	}
	var token []byte
	if d.tokenFile != "" {
		token, err = install.ReadDiscordTokenFile(d.tokenFile)
	} else if interactive {
		if _, err := fmt.Fprint(view.out, "      Bot token (input hidden): "); err != nil {
			return install.ModuleInstallSettings{}, err
		}
		token, err = term.ReadPassword(stdin.Fd())
		_, writeErr := fmt.Fprintln(view.out)
		err = errors.Join(err, writeErr)
	} else {
		return install.ModuleInstallSettings{}, errors.New("Discord setup requires --discord-token-file outside an interactive terminal")
	}
	if err != nil {
		clear(token)
		return install.ModuleInstallSettings{}, err
	}
	settings.Discord = &install.DiscordSetup{ApplicationID: application, BotUserID: bot, Token: token}
	return settings, nil
}
