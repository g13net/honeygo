package sandbox

import (
	"fmt"
	"strings"
)

type Shell struct {
	cwd      string
	hostname string
	user     string
}

func NewShell(user, hostname string) *Shell {
	return &Shell{
		cwd:      "/home/" + user,
		hostname: hostname,
		user:     user,
	}
}

func (s *Shell) Prompt() string {
	return fmt.Sprintf("%s@%s:%s$ ", s.user, s.hostname, s.cwd)
}

func (s *Shell) Execute(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}

	parts := strings.Split(input, " ")
	cmd := parts[0]

	switch cmd {
	case "ls":
		return "total 0\n-rw-r--r-- 1 user user 0 Mar 27 10:00 notes.txt"
	case "pwd":
		return s.cwd
	case "whoami":
		return s.user
	case "hostname":
		return s.hostname
	case "cat":
		if len(parts) > 1 && parts[1] == "notes.txt" {
			return "Remember to change the admin password!"
		}
		return "cat: " + parts[1] + ": No such file or directory"
	case "exit":
		return "exit"
	default:
		return fmt.Sprintf("-bash: %s: command not found", cmd)
	}
}
