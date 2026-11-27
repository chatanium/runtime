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
	name := cmd.CalledAs()
	if name == "" {
		name = cmd.Name()
	}
	view := terminalView{out: out, area: "[ " + strings.ToUpper(name) + " ]"}
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

func (v terminalView) prefix(state string) string {
	style := "1;36"
	switch state {
	case "OK", "READY", "RUNNING", "STOPPED":
		style = "1;32"
	case "REVIEW", "WARN", "CANCEL":
		style = "1;33"
	case "FAIL", "FAILED":
		style = "1;31"
	}
	return v.paint(v.area, "1;36") + " " + v.paint("["+state+"]", style)
}

func (v terminalView) status(state, text string) error {
	_, err := fmt.Fprintf(v.out, "%s %s\n", v.prefix(state), safeTerminalText(text))
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
