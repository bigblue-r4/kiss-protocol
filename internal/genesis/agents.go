package genesis

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// KnownAgentIndicators are paths and binaries that indicate an AI agent
// is already installed on this machine. If any are present at genesis time,
// the operator should be warned — the genesis snapshot will be less trustworthy
// because the agent had machine access before the witness was established.
var KnownAgentIndicators = []AgentIndicator{
	// Claude Code
	{Name: "claude-code", Type: "binary", Path: "claude"},
	{Name: "claude-code-config", Type: "dir", Path: "~/.claude"},
	// OpenAI / GPT agents
	{Name: "openai-cli", Type: "binary", Path: "openai"},
	{Name: "chatgpt-cli", Type: "binary", Path: "chatgpt"},
	// Cursor
	{Name: "cursor", Type: "binary", Path: "cursor"},
	// Continue.dev
	{Name: "continue", Type: "dir", Path: "~/.continue"},
	// Aider
	{Name: "aider", Type: "binary", Path: "aider"},
	// AutoGPT / AutoGen
	{Name: "autogpt", Type: "dir", Path: "~/Auto-GPT"},
	{Name: "autogen", Type: "binary", Path: "autogen"},
	// LangChain / LangGraph
	{Name: "langchain", Type: "pypackage", Path: "langchain"},
	// Copilot CLI
	{Name: "github-copilot", Type: "binary", Path: "gh-copilot"},
	// Generic MCP server indicator
	{Name: "mcp-server", Type: "dir", Path: "~/.mcp"},
	// Python AI packages (pip-installed)
	{Name: "anthropic-sdk", Type: "pypackage", Path: "anthropic"},
	{Name: "openai-sdk", Type: "pypackage", Path: "openai"},
}

// AgentIndicator describes one known agent detection check.
type AgentIndicator struct {
	Name string // human-readable
	Type string // "binary", "dir", "pypackage"
	Path string // path or package name
}

// AgentPresence is one detected agent at genesis.
type AgentPresence struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Path  string `json:"path"`
	Found string `json:"found"` // resolved path or version
}

// ScanForAgents checks for known AI agent indicators on this machine.
// Returns detected agents. An empty slice means the machine is clean.
func ScanForAgents() []AgentPresence {
	var found []AgentPresence
	home, _ := os.UserHomeDir()

	for _, ind := range KnownAgentIndicators {
		path := strings.Replace(ind.Path, "~", home, 1)
		switch ind.Type {
		case "binary":
			if resolved, err := exec.LookPath(path); err == nil {
				found = append(found, AgentPresence{
					Name:  ind.Name,
					Type:  ind.Type,
					Path:  ind.Path,
					Found: resolved,
				})
			}
		case "dir":
			if _, err := os.Stat(path); err == nil {
				found = append(found, AgentPresence{
					Name:  ind.Name,
					Type:  ind.Type,
					Path:  ind.Path,
					Found: path,
				})
			}
		case "pypackage":
			if loc := findPyPackage(ind.Path); loc != "" {
				found = append(found, AgentPresence{
					Name:  ind.Name,
					Type:  ind.Type,
					Path:  ind.Path,
					Found: loc,
				})
			}
		}
	}
	return found
}

func findPyPackage(pkg string) string {
	// Try pip show
	out, err := exec.Command("pip3", "show", pkg).Output()
	if err == nil && len(out) > 0 {
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "Location:") {
				loc := strings.TrimSpace(strings.TrimPrefix(line, "Location:"))
				return filepath.Join(loc, pkg)
			}
		}
		return pkg + " (pip)"
	}
	return ""
}
