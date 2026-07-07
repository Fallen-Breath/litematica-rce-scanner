package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"strings"
)

type options struct {
	concurrency      int
	csvPath          string
	colorMode        string
	colorEnabled     bool
	progress         bool
	warnings         bool
	nonRecursive     bool
	pause            bool
	noPause          bool
	failOnVulnerable bool
	showVersion      bool
}

func run(args []string) (int, bool) {
	opts, roots, err := parseOptions(args)
	pause := shouldPauseAtExit(args, opts)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0, pause
		}
		fmt.Fprintf(os.Stdout, "Error: %v\n", err)
		return 2, pause
	}
	opts.colorEnabled = shouldUseColor(opts.colorMode, os.Stdout)
	if opts.showVersion {
		fmt.Printf("litematica-rce-scanner %s\n", version)
		return 0, pause
	}

	summary, err := scanRoots(roots, opts)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error: %v\n", err)
		return 2, pause
	}

	printSummary(summary, colorizer{enabled: opts.colorEnabled})
	if opts.failOnVulnerable && summary.VulnerableJars > 0 {
		return 1, pause
	}
	return 0, pause
}

func parseOptions(args []string) (options, []string, error) {
	opts := options{
		concurrency: 1,
		colorMode:   "auto",
		progress:    true,
	}

	fs := flag.NewFlagSet("litematica-rce-scanner", flag.ContinueOnError)
	fs.SetOutput(os.Stdout)
	fs.IntVar(&opts.concurrency, "j", opts.concurrency, "number of files to scan concurrently")
	fs.IntVar(&opts.concurrency, "concurrency", opts.concurrency, "number of files to scan concurrently")
	fs.StringVar(&opts.csvPath, "csv", "", "write detected Litematica/Servux jar results to a CSV file")
	fs.StringVar(&opts.colorMode, "color", opts.colorMode, "color output mode: auto, always, never")
	fs.BoolVar(&opts.progress, "progress", opts.progress, "print periodic progress to stdout")
	fs.BoolVar(&opts.warnings, "warnings", false, "print per-file warnings for scan failures")
	fs.BoolVar(&opts.nonRecursive, "non-recursive", false, "scan only immediate files under each directory, do not recurse into subdirectories")
	fs.BoolVar(&opts.pause, "pause", false, "wait for Enter before exiting")
	fs.BoolVar(&opts.noPause, "no-pause", false, "disable automatic Windows pause")
	fs.BoolVar(&opts.failOnVulnerable, "fail-on-vulnerable", false, "exit with code 1 if any vulnerable jar is found")
	fs.BoolVar(&opts.showVersion, "version", false, "print version information and exit")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage: %s [options] [path ...]\n\n", fs.Name())
		fmt.Fprintln(fs.Output(), "Scan regular files under each path. Directory scanning is recursive unless -non-recursive is set.")
		fmt.Fprintln(fs.Output(), "\nOptions:")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		return opts, nil, err
	}
	if opts.concurrency < 1 {
		return opts, nil, fmt.Errorf("concurrency must be at least 1")
	}
	switch opts.colorMode {
	case "auto", "always", "never":
	default:
		return opts, nil, fmt.Errorf("color must be auto, always, or never")
	}

	roots := fs.Args()
	if len(roots) == 0 {
		roots = []string{"."}
	}
	return opts, roots, nil
}

func shouldPauseAtExit(args []string, opts options) bool {
	if opts.noPause {
		return false
	}
	if opts.pause {
		return true
	}
	if runtime.GOOS != "windows" {
		return false
	}
	if argsContainFlag(args) {
		return false
	}
	return isCharacterDevice(os.Stdin) && isCharacterDevice(os.Stdout)
}

func argsContainFlag(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "-") && arg != "-" {
			return true
		}
	}
	return false
}

func isCharacterDevice(file *os.File) bool {
	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func waitForEnter() {
	fmt.Fprint(os.Stdout, "Press Enter to exit...")
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
