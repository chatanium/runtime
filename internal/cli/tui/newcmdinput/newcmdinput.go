package newcmdinput

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/thirdscam/chatanium/internal/scaffold"
)

type step uint8

const (
	chooseTemplate step = iota
	enterName
	review
	confirmed
	canceled
)

type Model struct {
	step  step
	opts  scaffold.Options
	input textinput.Model
	err   error
}

func New(opts scaffold.Options) Model {
	input := textinput.New()
	input.Placeholder = "my-module"
	input.Width = 30
	return Model{opts: opts, input: input}
}

func (m Model) Init() tea.Cmd { return nil }

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyMsg); ok {
		if key.Type == tea.KeyEsc || key.Type == tea.KeyCtrlC {
			m.step = canceled
			return m, tea.Quit
		}
		switch m.step {
		case chooseTemplate:
			switch key.Type {
			case tea.KeyUp, tea.KeyDown:
				if m.opts.Template == scaffold.Local {
					m.opts.Template = scaffold.Discord
				} else {
					m.opts.Template = scaffold.Local
				}
			case tea.KeyEnter:
				m.step = enterName
				cmd := m.input.Focus()
				return m, cmd
			}
			return m, nil
		case enterName:
			m.err = nil
			if key.Type == tea.KeyEnter {
				name := m.input.Value()
				path, err := scaffold.Destination(name, m.opts.Directory)
				if err != nil {
					m.err = err
					return m, nil
				}
				m.opts.Name = name
				m.opts.Directory = path
				m.step = review
				m.input.Blur()
				return m, nil
			}
		case review:
			switch key.String() {
			case "y", "Y":
				m.step = confirmed
				return m, tea.Quit
			case "n", "N", "enter":
				m.step = canceled
				return m, tea.Quit
			}
		}
	}
	if m.step == enterName {
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) View() string {
	label := "Local check"
	if m.opts.Template == scaffold.Discord {
		label = "Discord bot"
	}
	switch m.step {
	case chooseTemplate:
		local, discord := ">", " "
		if m.opts.Template == scaffold.Discord {
			local, discord = discord, local
		}
		return fmt.Sprintf("Choose a module template\n\n%s Local check\n%s Discord bot\n\n↑/↓ select · Enter continue · Esc cancel\n", local, discord)
	case enterName:
		view := fmt.Sprintf("Template: %s\nModule name:\n%s\n\nEnter continue · Esc cancel\n", label, m.input.View())
		if m.err != nil {
			view += m.err.Error() + "\n"
		}
		return view
	case review:
		return fmt.Sprintf("Template: %s\nModule name: %s\nPath: %s\n\nCreate this module? [y/N] · Esc cancel\n", label, m.opts.Name, m.opts.Directory)
	default:
		return ""
	}
}

func (m Model) Result() (scaffold.Options, bool) {
	return m.opts, m.step == confirmed
}
