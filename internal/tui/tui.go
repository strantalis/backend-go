package tui

import (
	"fmt"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

const (
	ProfileName = iota
	OidcDiscoveryEndpoint
	KasEndpoint
	ClientID
	ClientSecret
)

type (
	errMsg error
)

const (
	hotPink  = lipgloss.Color("#FF06B7")
	darkGray = lipgloss.Color("#767676")
)

var (
	inputStyle    = lipgloss.NewStyle().Foreground(hotPink)
	continueStyle = lipgloss.NewStyle().Foreground(darkGray)
)

type Model struct {
	Inputs  []textinput.Model
	focused int
	err     error
	Quit    bool
}

func InitialModel() Model {
	var inputs []textinput.Model = make([]textinput.Model, 5)
	inputs[ProfileName] = textinput.New()
	inputs[ProfileName].Placeholder = "Profile Name"
	inputs[ProfileName].Focus()
	inputs[ProfileName].CharLimit = 156
	inputs[ProfileName].Width = 20
	inputs[OidcDiscoveryEndpoint] = textinput.New()
	inputs[OidcDiscoveryEndpoint].Placeholder = "OIDC Endpoint"
	inputs[OidcDiscoveryEndpoint].CharLimit = 156
	inputs[OidcDiscoveryEndpoint].Width = 100
	inputs[KasEndpoint] = textinput.New()
	inputs[KasEndpoint].Placeholder = "Kas Endpoint"
	inputs[KasEndpoint].CharLimit = 156
	inputs[KasEndpoint].Width = 100
	inputs[ClientID] = textinput.New()
	inputs[ClientID].Placeholder = "Client ID"
	inputs[ClientID].CharLimit = 156
	inputs[ClientID].Width = 20
	inputs[ClientSecret] = textinput.New()
	inputs[ClientSecret].Placeholder = "Client Secret"
	inputs[ClientSecret].CharLimit = 156
	inputs[ClientSecret].Width = 40

	return Model{
		Inputs: inputs,
	}
}

func (m Model) Init() tea.Cmd {
	// Just return `nil`, which means "no I/O right now, please."
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd = make([]tea.Cmd, len(m.Inputs))
	switch msg := msg.(type) {

	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			if m.focused == len(m.Inputs)-1 {
				return m, tea.Quit
			}
			m.nextInput()
		case tea.KeyCtrlC, tea.KeyEsc:
			m.Quit = true
			return m, tea.Quit
		case tea.KeyShiftTab, tea.KeyCtrlP:
			m.prevInput()
		case tea.KeyTab, tea.KeyCtrlN:
			m.nextInput()
		}
		for i := range m.Inputs {
			m.Inputs[i].Blur()
		}
		m.Inputs[m.focused].Focus()

	// We handle errors just like any other message
	case errMsg:
		m.err = msg
		return m, nil
	}

	for i := range m.Inputs {
		m.Inputs[i], cmds[i] = m.Inputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m Model) View() string {
	// The header
	return fmt.Sprintf(
		`
 %s  %s
 %s  %s
 %s  %s
 %s  %s
 %s  %s

 %s
`,
		inputStyle.Width(24).Render("Profile Name"),
		m.Inputs[ProfileName].View(),
		inputStyle.Width(24).Render("OIDC Endpoint"),
		m.Inputs[OidcDiscoveryEndpoint].View(),
		inputStyle.Width(24).Render("KAS Endpoint"),
		m.Inputs[KasEndpoint].View(),
		inputStyle.Width(24).Render("Client ID"),
		m.Inputs[ClientID].View(),
		inputStyle.Width(24).Render("Client Secret"),
		m.Inputs[ClientSecret].View(),
		continueStyle.Render("Submit ->"),
	) + "\n"
}

// nextInput focuses the next input field
func (m *Model) nextInput() {
	m.focused = (m.focused + 1) % len(m.Inputs)
}

// prevInput focuses the previous input field
func (m *Model) prevInput() {
	m.focused--
	// Wrap around
	if m.focused < 0 {
		m.focused = len(m.Inputs) - 1
	}
}
