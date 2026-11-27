package cmd

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"unicode"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

type terminalView struct {
	out      io.Writer
	area     string
	terminal bool
	color    bool
}

func commandView(cmd *cobra.Command, out io.Writer) terminalView {
	view := terminalView{out: out, area: commandArea(cmd)}
	if f, ok := out.(*os.File); ok && os.Getenv("TERM") != "dumb" && os.Getenv("CI") == "" &&
		(isatty.IsTerminal(f.Fd()) || isatty.IsCygwinTerminal(f.Fd())) {
		view.terminal = true
		if os.Getenv("NO_COLOR") == "" {
			view.color = true
			view.out = colorable.NewColorable(f)
		}
	}
	return view
}

func commandArea(cmd *cobra.Command) string {
	if parent := cmd.Parent(); cmd.Name() == "acl" || parent != nil && parent.Name() == "acl" {
		return "ACL"
	}
	name := cmd.CalledAs()
	if name == "" {
		name = cmd.Name()
	}
	switch name {
	case "serve", "stop":
		return "RUNTIME"
	case "doctor":
		return "DOCTOR"
	case "init":
		return "INIT"
	case "reset":
		return "RESET"
	case "new", "module", "install":
		return "MODULE"
	case "prepare-image":
		return "IMAGE"
	case "generate-config", "configure", "inspect-config":
		return "CONFIG"
	case "update":
		return "UPDATE"
	case "uninstall":
		return "UNINSTALL"
	case "purge":
		return "PURGE"
	case "bind-restored-volumes":
		return "RESTORE"
	default:
		return "CLI"
	}
}

func jsonOutputFlag(cmd *cobra.Command) {
	cmd.Flags().Bool("json", false, "emit machine-readable JSON even in a terminal")
}

func operatorOutput(cmd *cobra.Command) (terminalView, bool) {
	view := commandView(cmd, cmd.OutOrStdout())
	machine, _ := cmd.Flags().GetBool("json")
	return view, view.terminal && !machine
}

func (v terminalView) paint(text, style string) string {
	if !v.color {
		return text
	}
	return "\x1b[" + style + "m" + text + "\x1b[0m"
}

type logLevel string

const (
	logInfo  logLevel = "INFO"
	logError logLevel = "ERR!"
	logWarn  logLevel = "WARN"
	logDebug logLevel = "DEBG"
)

func (v terminalView) log(level logLevel, text string) error {
	message := safeTerminalText(text)
	tag, area := "["+string(level)+"]", "["+v.area+"]"
	if level == logError {
		_, err := fmt.Fprintln(v.out, v.paint(tag+" "+area+" "+message, "1;31"))
		return err
	}
	style := "1;36"
	switch level {
	case logWarn:
		style = "1;33"
	case logDebug:
		style = "2"
	}
	_, err := fmt.Fprintf(v.out, "%s %s %s\n", v.paint(tag, style), v.paint(area, "1"), message)
	return err
}

func (v terminalView) detail(label, text string) error {
	return v.indented(v.paint(label+":", "1") + " " + safeTerminalText(text))
}

func (v terminalView) indented(text string) error {
	_, err := fmt.Fprintln(v.out, "      "+text)
	return err
}

func safeTerminalText(text string) string {
	if strings.IndexFunc(text, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) >= 0 {
		return strconv.Quote(text)
	}
	return text
}
