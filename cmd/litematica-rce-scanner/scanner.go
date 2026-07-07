package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

type counters struct {
	startedAt      time.Time
	scanned        uint64
	validZips      uint64
	targetJars     uint64
	targetClasses  uint64
	vulnerableJars uint64
	errors         uint64
}

type scanResult struct {
	Path       string
	Mod        string
	Version    string
	Vulnerable bool
	Error      string
}

type scanSummary struct {
	Elapsed        time.Duration
	Scanned        uint64
	ValidZips      uint64
	TargetJars     uint64
	TargetClasses  uint64
	VulnerableJars uint64
	Errors         uint64
}

func scanRoots(roots []string, opts options) (scanSummary, error) {
	c := counters{startedAt: time.Now()}
	colors := colorizer{enabled: opts.colorEnabled}
	validRoots := make([]string, 0, len(roots))
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			atomic.AddUint64(&c.errors, 1)
			printWarning(opts, "cannot access root %q: %v", root, err)
			continue
		}
		validRoots = append(validRoots, root)
	}
	if len(validRoots) == 0 {
		return snapshotCounters(&c), fmt.Errorf("no readable scan roots")
	}

	csvFile, csvWriter, err := openCSV(opts.csvPath)
	if err != nil {
		return snapshotCounters(&c), err
	}
	if csvFile != nil {
		defer csvFile.Close()
	}

	jobs := make(chan string, opts.concurrency*4)
	results := make(chan scanResult, opts.concurrency*2)
	consumerDone := make(chan error, 1)
	go consumeResults(results, csvWriter, colors, consumerDone)

	stopProgress := make(chan struct{})
	progressDone := make(chan struct{})
	if opts.progress {
		go reportProgress(&c, colors, stopProgress, progressDone)
	}

	printLine(colors.cyan(fmt.Sprintf("Scanning %d root(s) with concurrency %d", len(validRoots), opts.concurrency)))

	var wg sync.WaitGroup
	for i := 0; i < opts.concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				scanOne(path, &c, opts, results)
			}
		}()
	}

	for _, root := range validRoots {
		walkRoot(root, jobs, &c, opts)
	}
	close(jobs)
	wg.Wait()
	close(results)

	if opts.progress {
		close(stopProgress)
		<-progressDone
	}
	if err := <-consumerDone; err != nil {
		return snapshotCounters(&c), err
	}
	if opts.progress {
		printProgress(snapshotCounters(&c), colors)
	}
	return snapshotCounters(&c), nil
}

func walkRoot(root string, jobs chan<- string, c *counters, opts options) {
	if opts.nonRecursive {
		walkRootNonRecursive(root, jobs, c, opts)
		return
	}

	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			atomic.AddUint64(&c.errors, 1)
			printWarning(opts, "cannot read %q: %v", path, walkErr)
			return nil
		}
		enqueueDirEntry(path, entry, jobs)
		return nil
	})
	if err != nil {
		atomic.AddUint64(&c.errors, 1)
		printWarning(opts, "cannot walk %q: %v", root, err)
	}
}

func walkRootNonRecursive(root string, jobs chan<- string, c *counters, opts options) {
	info, err := os.Stat(root)
	if err != nil {
		atomic.AddUint64(&c.errors, 1)
		printWarning(opts, "cannot access %q: %v", root, err)
		return
	}
	if info.Mode().IsRegular() {
		jobs <- root
		return
	}
	if !info.IsDir() {
		return
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		atomic.AddUint64(&c.errors, 1)
		printWarning(opts, "cannot read %q: %v", root, err)
		return
	}
	for _, entry := range entries {
		enqueueDirEntry(filepath.Join(root, entry.Name()), entry, jobs)
	}
}

func enqueueDirEntry(path string, entry os.DirEntry, jobs chan<- string) {
	if entry.IsDir() {
		return
	}
	if entry.Type()&os.ModeType != 0 {
		return
	}
	jobs <- path
}

func scanOne(path string, c *counters, opts options, results chan<- scanResult) {
	atomic.AddUint64(&c.scanned, 1)
	findings, validZip, err := inspectZip(path)
	if err != nil {
		atomic.AddUint64(&c.errors, 1)
		printWarning(opts, "cannot scan %q: %v", path, err)
		return
	}
	if validZip {
		atomic.AddUint64(&c.validZips, 1)
	}
	if len(findings) == 0 {
		return
	}

	atomic.AddUint64(&c.targetJars, 1)
	vulnerableJar := false
	for _, finding := range findings {
		atomic.AddUint64(&c.targetClasses, 1)
		if finding.Error != "" {
			atomic.AddUint64(&c.errors, 1)
			printWarning(opts, "cannot inspect target class in %q: %s", path, finding.Error)
			continue
		}
		if finding.Vulnerable {
			vulnerableJar = true
		}
		results <- finding
	}
	if vulnerableJar {
		atomic.AddUint64(&c.vulnerableJars, 1)
	}
}

func printWarning(opts options, format string, args ...any) {
	if !opts.warnings {
		return
	}
	printf("Warning: "+format+"\n", args...)
}

func snapshotCounters(c *counters) scanSummary {
	return scanSummary{
		Elapsed:        time.Since(c.startedAt),
		Scanned:        atomic.LoadUint64(&c.scanned),
		ValidZips:      atomic.LoadUint64(&c.validZips),
		TargetJars:     atomic.LoadUint64(&c.targetJars),
		TargetClasses:  atomic.LoadUint64(&c.targetClasses),
		VulnerableJars: atomic.LoadUint64(&c.vulnerableJars),
		Errors:         atomic.LoadUint64(&c.errors),
	}
}
