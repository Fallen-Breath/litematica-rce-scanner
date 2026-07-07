package main

import (
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
)

const progressInterval = 5 * time.Second

var (
	outputMu sync.Mutex
	stdout   io.Writer = colorable.NewColorableStdout()
)

type colorizer struct {
	enabled bool
}

func openCSV(path string) (*os.File, *csv.Writer, error) {
	if path == "" {
		return nil, nil, nil
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create CSV file %q: %w", path, err)
	}
	writer := csv.NewWriter(file)
	if err := writer.Write([]string{"path", "mod", "status", "version"}); err != nil {
		file.Close()
		return nil, nil, fmt.Errorf("cannot write CSV header: %w", err)
	}
	return file, writer, nil
}

func consumeResults(results <-chan scanResult, writer *csv.Writer, colors colorizer, done chan<- error) {
	var firstErr error
	for result := range results {
		printResult(result, colors)
		if writer != nil && firstErr == nil {
			if err := writer.Write([]string{result.Path, result.Mod, resultStatus(result), result.Version}); err != nil {
				firstErr = fmt.Errorf("cannot write CSV row: %w", err)
			}
		}
	}
	if writer != nil && firstErr == nil {
		writer.Flush()
		if err := writer.Error(); err != nil {
			firstErr = fmt.Errorf("cannot flush CSV file: %w", err)
		}
	}
	done <- firstErr
}

func printShortBanner() {
	printLine(fmt.Sprintf("%s v%s", appName, version))
}

func printVersionBanner() {
	printLine(fmt.Sprintf("%s v%s, licensed under %s", appName, version, license))
	printLine(fmt.Sprintf("Project URL: %s", projectURL))
}

func reportProgress(c *counters, colors colorizer, stop <-chan struct{}, done chan<- struct{}) {
	ticker := time.NewTicker(progressInterval)
	defer ticker.Stop()
	defer close(done)
	for {
		select {
		case <-ticker.C:
			printProgress(snapshotCounters(c), colors)
		case <-stop:
			return
		}
	}
}

func printProgress(summary scanSummary, colors colorizer) {
	message := fmt.Sprintf("Progress: scanned %d files, elapsed %s",
		summary.Scanned,
		formatDuration(summary.Elapsed),
	)
	if summary.VulnerableJars > 0 {
		message += fmt.Sprintf(", vulnerable %d", summary.VulnerableJars)
	}
	if summary.Errors > 0 {
		message += fmt.Sprintf(", errors %d", summary.Errors)
	}
	printLine(colors.dim(message))
}

func printResult(result scanResult, colors colorizer) {
	const labelWidth = len("[VULNERABLE]")

	labelText := "[SAFE]"
	if result.Vulnerable {
		labelText = "[VULNERABLE]"
	}
	label := colors.green(labelText)
	if result.Vulnerable {
		label = colors.red(labelText)
	}

	line := label + strings.Repeat(" ", labelWidth-len(labelText)+2) + result.Path + colors.dim("   ") + colors.magenta(result.Mod)
	if result.Version != "" {
		line += " " + colors.cyan("v"+result.Version)
	}
	printLine(line)
}

func formatDuration(duration time.Duration) string {
	return fmt.Sprintf("%.1fs", duration.Seconds())
}

func resultStatus(result scanResult) string {
	if result.Vulnerable {
		return "vulnerable"
	}
	return "safe"
}

func printSummary(summary scanSummary, colors colorizer) {
	outputMu.Lock()
	defer outputMu.Unlock()

	fmt.Fprintln(stdout)
	fmt.Fprintln(stdout, "Summary:")
	fmt.Fprintf(stdout, "  Files scanned: %d\n", summary.Scanned)
	fmt.Fprintf(stdout, "  Valid zip/jar files: %d\n", summary.ValidZips)
	fmt.Fprintf(stdout, "  Jars with target class: %d\n", summary.TargetJars)
	fmt.Fprintf(stdout, "  Target classes inspected: %d\n", summary.TargetClasses)
	fmt.Fprintf(stdout, "  Safe jars: %s\n", coloredCount(summary.SafeJars, colors.green))
	fmt.Fprintf(stdout, "  Vulnerable jars: %s\n", coloredCount(summary.VulnerableJars, colors.red))
	fmt.Fprintf(stdout, "  Errors: %d\n", summary.Errors)
	if summary.VulnerableJars == 0 {
		fmt.Fprintln(stdout, colors.green("No vulnerable jars found."))
	} else {
		fmt.Fprintln(stdout, colors.red("Vulnerable jars were found."))
		fmt.Fprintln(stdout, "")
		fmt.Fprintln(stdout, "Please update the affected mods as soon as possible to avoid being impacted.")
		fmt.Fprintf(stdout, "  Litematica: %s\n", colors.link("https://modrinth.com/mod/litematica/versions"))
		fmt.Fprintf(stdout, "  Servux: %s\n", colors.link("https://modrinth.com/mod/servux/versions"))
	}
}

func coloredCount(value uint64, paint func(string) string) string {
	text := fmt.Sprint(value)
	if value == 0 {
		return text
	}
	return paint(text)
}

func printLine(line string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Fprintln(stdout, line)
}

func printf(format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Fprintf(stdout, format, args...)
}

func shouldUseColor(mode string, file *os.File) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default:
		return isatty.IsTerminal(file.Fd()) || isatty.IsCygwinTerminal(file.Fd())
	}
}

func (c colorizer) paint(code string, text string) string {
	if !c.enabled {
		return text
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

func (c colorizer) red(text string) string {
	return c.paint("31;1", text)
}

func (c colorizer) cyan(text string) string {
	return c.paint("36", text)
}

func (c colorizer) magenta(text string) string {
	return c.paint("35", text)
}

func (c colorizer) green(text string) string {
	return c.paint("32;1", text)
}

func (c colorizer) link(text string) string {
	return c.paint("34;4", text)
}

func (c colorizer) dim(text string) string {
	return c.paint("2", text)
}
