package main

import "os"

func main() {
	code, pause := run(os.Args[1:])
	if pause {
		waitForEnter()
	}
	os.Exit(code)
}
