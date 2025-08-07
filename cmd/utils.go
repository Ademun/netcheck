package cmd

import (
	"os"
	"os/exec"
	"runtime"
)

func ClearScreen() {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls") // For Windows
	default:
		cmd = exec.Command("clear") // For Linux/macOS
	}
	cmd.Stdout = os.Stdout
	cmd.Run()
}
