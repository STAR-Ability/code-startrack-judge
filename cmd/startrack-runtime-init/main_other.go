//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() { fmt.Fprintln(os.Stderr, "supervisor Linux platform failure"); os.Exit(1) }
