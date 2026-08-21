package main

import (
	"os"

	"github.com/greentruth/imgvet/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
