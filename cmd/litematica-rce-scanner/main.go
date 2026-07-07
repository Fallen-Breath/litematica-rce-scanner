package main

import "os"

var version = "0.2.0"

func main() {
	code, pause := run(os.Args[1:])
	if pause {
		waitForEnter()
	}
	os.Exit(code)
}
