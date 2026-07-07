package main

import (
	"encoding/csv"
	"fmt"
	"os"
	"sync"
	"time"
)

const progressInterval = 5 * time.Second

var outputMu sync.Mutex

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
	label := colors.green("[SAFE]")
	if result.Vulnerable {
		label = colors.red("[VULNERABLE]")
	}
	line := fmt.Sprintf("%s %s%s%s", label, result.Path, colors.dim(" | "), colors.magenta(result.Mod))
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

	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Summary:")
	fmt.Fprintf(os.Stdout, "  Files scanned: %d\n", summary.Scanned)
	fmt.Fprintf(os.Stdout, "  Valid zip/jar files: %d\n", summary.ValidZips)
	fmt.Fprintf(os.Stdout, "  Jars with target class: %d\n", summary.TargetJars)
	fmt.Fprintf(os.Stdout, "  Target classes inspected: %d\n", summary.TargetClasses)
	fmt.Fprintf(os.Stdout, "  Vulnerable jars: %d\n", summary.VulnerableJars)
	fmt.Fprintf(os.Stdout, "  Errors: %d\n", summary.Errors)
	if summary.VulnerableJars == 0 {
		fmt.Fprintln(os.Stdout, colors.green("No vulnerable jars found."))
	} else {
		fmt.Fprintln(os.Stdout, colors.red("Vulnerable jars were found."))
	}
}

func printLine(line string) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Fprintln(os.Stdout, line)
}

func printf(format string, args ...any) {
	outputMu.Lock()
	defer outputMu.Unlock()
	fmt.Fprintf(os.Stdout, format, args...)
}

func shouldUseColor(mode string, file *os.File) bool {
	switch mode {
	case "always":
		return true
	case "never":
		return false
	default:
		return isCharacterDevice(file)
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

func (c colorizer) dim(text string) string {
	return c.paint("2", text)
}
