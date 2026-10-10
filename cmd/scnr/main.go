// Command scnr is a defensive vulnerability discovery CLI.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/gerald/scnr/internal/cli"
)

// version is set by the release build (-ldflags "-X main.version=...").
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	app := cli.NewApp(version)
	app.IsTTY = isTerminal(os.Stdin) && isTerminal(os.Stdout)
	os.Exit(cli.Execute(ctx, app, os.Args[1:]))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
