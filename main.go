package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/intruder-io/gitreaper/internal/fetch"
	"github.com/intruder-io/gitreaper/internal/git"
	"github.com/intruder-io/gitreaper/internal/scan"
)

func main() {
	var (
		urlsFile    = flag.String("urls", "", "File containing one URL per line")
		workers     = flag.Int("workers", 5, "Number of repos to scan concurrently")
		blobWorkers = flag.Int("blob-workers", 10, "Concurrent blob fetches per repo")
		timeout     = flag.Duration("timeout", 30*time.Second, "HTTP request timeout")
		maxBlob     = flag.Int64("max-blob", 1<<20, "Maximum blob size in bytes to scan (0 = unlimited)")
		maxPack     = flag.Int64("max-pack", 0, "Maximum pack file size to download in bytes (0 = unlimited)")
		maxRefs     = flag.Int("max-refs", 0, "Maximum number of refs to walk per repo (0 = unlimited; use with mass scanning)")
		repoTimeout = flag.Duration("repo-timeout", 0, "Per-repo scan time limit (0 = unlimited; e.g. 60s)")
		noHistory   = flag.Bool("no-history", false, "Scan HEAD commit only, skip full history")
		noFPReduce  = flag.Bool("no-fp-reduction", false, "Disable false-positive filtering (report all raw matches)")
		jsonOut     = flag.Bool("json", false, "Output findings as NDJSON (one JSON object per line)")
		content     = flag.Bool("content", false, "Include full file content in JSON findings")
		outFile     = flag.String("o", "", "Write output to this file instead of stdout")
		outDir      = flag.String("out-dir", "", "Write per-target findings as JSON to this directory (one file per target)")
		dumpDir     = flag.String("dump", "", "Dump HEAD-state working tree of each repo into this directory")
		dumpHead    = flag.Bool("dump-head", false, "With -dump: write only the HEAD snapshot of each branch (flat files, no commit history)")
		lootDir     = flag.String("loot", "", "Save full file content for any file containing a finding, organized by host under this directory")
		verbose        = flag.Bool("v", false, "Verbose logging")
		progress       = flag.Bool("progress", false, "Show a live status bar on stderr")
		rulesFile      = flag.String("rules", "", "Path to a JSON rules file to load (merged with built-in rules unless -no-default-rules)")
		noDefaultRules = flag.Bool("no-default-rules", false, "Disable built-in rules (requires -rules)")
		enableGroups   = flag.String("enable-groups", "", "Comma-separated rule groups to enable (e.g. generic-credentials)")
		disableGroups  = flag.String("disable-groups", "", "Comma-separated rule groups to disable (e.g. path-sensitive,tokens-auth)")
		listGroups     = flag.Bool("list-groups", false, "List all rule groups and exit")
	)
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `gitreaper — scan exposed .git directories for secrets

Usage:
  gitreaper [flags] [url...]
  cat urls.txt | gitreaper [flags]

Each URL should point to an exposed .git directory, e.g.:
  https://example.com/.git

When -dump is used, each repo's HEAD working tree is written to:
  <dump-dir>/<hostname>_<path>/

When -out-dir is used, findings for each target are written as JSON to:
  <out-dir>/<hostname>.json

Rules are loaded from the built-in rules.json by default.
Use -rules to merge in (or replace with -no-default-rules) a custom JSON file.
Use -list-groups to see available groups and their default enabled status.
Use -enable-groups / -disable-groups to select specific groups at runtime.

Flags:
`)
		flag.PrintDefaults()
	}
	flag.Parse()

	if !*verbose {
		log.SetOutput(io.Discard)
	}

	// Load rules before anything else so -list-groups works without requiring URLs.
	var allRules []scan.Rule
	if !*noDefaultRules {
		allRules = scan.DefaultRules()
	}
	if *rulesFile != "" {
		extra, err := scan.LoadRulesFile(*rulesFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading rules file %s: %v\n", *rulesFile, err)
			os.Exit(1)
		}
		allRules = append(allRules, extra...)
	}

	if *listGroups {
		for _, g := range scan.ListGroups(allRules) {
			status := "on"
			if !g.Enabled {
				status = "off"
			}
			fmt.Printf("%-30s  %-8s  %-8s  %2d rules  %v\n", g.Name, g.Severity, status, g.Count, g.Tags)
		}
		return
	}

	rules := scan.ActiveRules(allRules, splitComma(*enableGroups), splitComma(*disableGroups))
	if len(rules) == 0 {
		fmt.Fprintln(os.Stderr, "error: no rules active — check -no-default-rules, -enable-groups, -disable-groups")
		os.Exit(1)
	}

	urls := collectURLs(flag.Args(), *urlsFile)
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "error: no URLs provided — pass as arguments, use -urls file, or pipe via stdin")
		flag.Usage()
		os.Exit(1)
	}

if *outDir != "" {
		if err := os.MkdirAll(*outDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "error: cannot create output directory %s: %v\n", *outDir, err)
			os.Exit(1)
		}
	}

	// con routes all stderr output so messages print cleanly above the status bar.
	con := &console{}
	if *progress {
		if fi, err := os.Stderr.Stat(); err == nil && fi.Mode()&os.ModeCharDevice != 0 {
			con.active = true
		}
	}

	out := openOutput(*outFile)
	defer out.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		outMu        sync.Mutex
		wg           sync.WaitGroup
		sem          = make(chan struct{}, *workers)
		findingCount atomic.Int64
		doneCount    atomic.Int64
		activeScans  sync.Map // repoURL -> *git.RepoScanner
	)

	// Start status bar goroutine.
	var stopStatus func()
	if con.active {
		statusCtx, statusCancel := context.WithCancel(context.Background())
		var statusWG sync.WaitGroup
		statusWG.Add(1)
		go func() {
			defer statusWG.Done()
			runStatusBar(statusCtx, len(urls), &activeScans, &findingCount, &doneCount, con)
		}()
		stopStatus = func() {
			statusCancel()
			statusWG.Wait()
			con.Clear()
		}
	}

	writeFinding := func(f scan.Finding) {
		findingCount.Add(1)
		outMu.Lock()
		defer outMu.Unlock()
		if *jsonOut {
			b, _ := json.Marshal(f)
			fmt.Fprintln(out, string(b))
		} else {
			commitShort := f.CommitHash
			if len(commitShort) > 8 {
				commitShort = commitShort[:8]
			}
			if f.LineNum == 0 {
				fmt.Fprintf(out, "[%s] commit:%s path:%s rule:%s severity:%s\n  interesting file: %s\n\n",
					f.RepoURL, commitShort, f.FilePath, f.RuleName, f.Severity, f.FilePath)
			} else {
				fmt.Fprintf(out, "[%s] commit:%s path:%s rule:%s severity:%s\n  line %d: %s\n\n",
					f.RepoURL, commitShort, f.FilePath, f.RuleName, f.Severity, f.LineNum, f.Line)
			}
		}
	}

loop:
	for _, rawURL := range urls {
		select {
		case <-ctx.Done():
			break loop
		case sem <- struct{}{}:
		}

		wg.Add(1)
		go func(rawURL string) {
			defer wg.Done()
			defer func() { <-sem }()

			repoURL := normalizeURL(rawURL)
			log.Printf("scanning %s", repoURL)

			scanner := &git.RepoScanner{
				URL:            repoURL,
				Client:         fetch.NewClient(*timeout),
				BlobWorkers:    *blobWorkers,
				MaxBlobSize:    *maxBlob,
				MaxPackSize:    *maxPack,
				MaxRefs:        *maxRefs,
				ScanTimeout:    *repoTimeout,
				NoHistory:      *noHistory,
				DumpDir:        *dumpDir,
				DumpHeadOnly:   *dumpHead,
				LootDir:        *lootDir,
				Verbose:        *verbose,
				NoFPReduction:  *noFPReduce,
				IncludeContent: *content,
				ErrWriter:      con,
			}

			activeScans.Store(repoURL, scanner)
			findings, err := scanner.Scan(ctx, rules)
			activeScans.Delete(repoURL)
			doneCount.Add(1)

			if err != nil && ctx.Err() == nil {
				con.PrintLine(fmt.Sprintf("error scanning %s: %v", repoURL, err))
				return
			}
			for _, f := range findings {
				writeFinding(f)
			}
			if *outDir != "" && len(findings) > 0 {
				writeTargetFile(*outDir, repoURL, findings)
			}
			if len(findings) == 0 {
				log.Printf("no findings for %s", repoURL)
			}
		}(rawURL)
	}

	wg.Wait()
	if stopStatus != nil {
		stopStatus()
	}
}

// writeTargetFile writes all findings for one repo as NDJSON to <outDir>/<host>.json.
func writeTargetFile(outDir, repoURL string, findings []scan.Finding) {
	fname := targetFilename(repoURL)
	path := filepath.Join(outDir, fname)
	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error creating %s: %v\n", path, err)
		return
	}
	defer f.Close()
	for _, finding := range findings {
		b, _ := json.Marshal(finding)
		fmt.Fprintln(f, string(b))
	}
}

// targetFilename returns a safe filename for a repo URL, e.g. "api.example.com.json".
func targetFilename(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil {
		return git.SanitizeName(repoURL) + ".json"
	}
	base := u.Host
	path := strings.Trim(strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/.git"), "/")
	if path != "" {
		base += "_" + path
	}
	return git.SanitizeName(base) + ".json"
}

// console manages stderr output so messages appear cleanly above the status bar.
type console struct {
	mu     sync.Mutex
	status string
	active bool // true when the progress bar is displayed
}

// Write implements io.Writer — used as git.RepoScanner.ErrWriter.
func (c *console) Write(p []byte) (int, error) {
	c.PrintLine(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// PrintLine clears the status bar, prints msg+newline, then reprints the bar.
func (c *console) PrintLine(msg string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
	fmt.Fprintln(os.Stderr, msg)
	if c.active && c.status != "" {
		fmt.Fprint(os.Stderr, c.status)
	}
}

// SetStatus updates the status bar content and redraws it.
func (c *console) SetStatus(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.status = s
	if c.active {
		fmt.Fprintf(os.Stderr, "\r\033[K%s", s)
	}
}

// Clear erases the status bar line.
func (c *console) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active {
		fmt.Fprint(os.Stderr, "\r\033[K")
	}
}

// runStatusBar periodically writes a status line via con until ctx is cancelled.
func runStatusBar(ctx context.Context, total int, active *sync.Map, findings, done *atomic.Int64, con *console) {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var blobs int64
			var hosts []string
			active.Range(func(k, v any) bool {
				hosts = append(hosts, urlHost(k.(string)))
				blobs += v.(*git.RepoScanner).BlobsProcessed.Load()
				return true
			})

			d := done.Load()
			f := findings.Load()
			line := fmt.Sprintf("[%d/%d] blobs:%s findings:%d",
				d, total, commaSep(blobs), f)

			switch len(hosts) {
			case 0:
				// nothing to append
			case 1:
				line += "  " + hosts[0]
			default:
				line += fmt.Sprintf("  %d active", len(hosts))
			}

			cols := termCols()
			if len(line) > cols {
				line = line[:cols-3] + "..."
			}
			con.SetStatus(line)
		}
	}
}

// termCols returns the terminal width, falling back to 120.
func termCols() int {
	if s := os.Getenv("COLUMNS"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 {
			return n
		}
	}
	return 120
}

// commaSep formats an integer with thousands separators.
func commaSep(n int64) string {
	s := strconv.FormatInt(n, 10)
	out := make([]byte, 0, len(s)+(len(s)-1)/3)
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// urlHost extracts the hostname from a URL string.
func urlHost(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// collectURLs gathers URLs from CLI arguments, a file, and/or stdin.
func collectURLs(args []string, urlsFile string) []string {
	var urls []string

	for _, u := range args {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, u)
		}
	}

	if urlsFile != "" {
		f, err := os.Open(urlsFile)
		if err != nil {
			log.Fatalf("open %s: %v", urlsFile, err)
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
	}

	// Read from stdin only if it is a pipe (not a terminal)
	if stat, _ := os.Stdin.Stat(); stat.Mode()&os.ModeCharDevice == 0 {
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
				urls = append(urls, line)
			}
		}
	}

	return urls
}

// normalizeURL ensures the URL points to a .git directory.
func normalizeURL(u string) string {
	u = strings.TrimRight(u, "/")
	if strings.HasSuffix(u, "/.git") {
		return u
	}
	if strings.HasSuffix(u, ".git") {
		u = strings.TrimSuffix(u, ".git")
	}
	return u + "/.git"
}

// splitComma splits a comma-separated string into a trimmed, non-empty slice.
func splitComma(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// openOutput returns a WriteCloser for the output destination.
func openOutput(path string) io.WriteCloser {
	if path == "" {
		return nopCloser{os.Stdout}
	}
	f, err := os.Create(path)
	if err != nil {
		log.Fatalf("create output file %s: %v", path, err)
	}
	return f
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }
