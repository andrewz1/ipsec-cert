package xcert

import (
	"fmt"
	"os"
	"os/exec"
)

const (
	shell = "sh"
)

func runScript() error {
	if len(opt.Script) == 0 {
		return nil
	}
	exe, err := exec.LookPath(shell)
	if err != nil {
		return err
	}
	args := []string{shell, "-c", opt.Script}
	env := make([]string, 0, 10)
	if sysPath := os.Getenv("PATH"); len(sysPath) != 0 {
		env = append(env, "PATH="+sysPath)
	}
	env = append(env, fmt.Sprintf("KEY_FILE=%s", opt.Key), fmt.Sprintf("CERT_FILE=%s", opt.Cert))
	cmd := exec.Cmd{Path: exe, Args: args, Env: env, Dir: "/"}
	return cmd.Run()
}
