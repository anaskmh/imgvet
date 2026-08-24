package main

import (
	"os"

	"github.com/anaskmh/imgvet/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
