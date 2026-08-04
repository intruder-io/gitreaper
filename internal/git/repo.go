package git

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/intruder-io/gitreaper/internal/fetch"
	"github.com/intruder-io/gitreaper/internal/scan"
)

// blobJob is work sent to blob worker goroutines.
// needScan and needDump are set independently so a job can be scan-only,
// dump-only, or both — avoiding redundant fetches while still covering all paths.
type blobJob struct {
	sha        string
	path       string
	commitHash string
	needScan   bool   // scan content for secrets (new SHA not yet scanned)
	needDump   bool   // write this path to disk (new path not yet written)
	dumpDir    string // if set, overrides the global dumpBase for this job
	fromIndex  bool   // sourced from .git/index — excluded from the blob-404 abort counter
}

// Ref is a named git reference pointing to a commit SHA.
type Ref struct {
	Name string // short name, e.g. "main", "staging"
	SHA  string
}

// RepoScanner fetches and scans an exposed git repository for secrets.
type RepoScanner struct {
	URL            string
	Client         *fetch.Client
	BlobWorkers    int
	MaxBlobSize    int64
	MaxPackSize    int64
	MaxRefs        int           // cap on starting refs to walk (0 = unlimited)
	ScanTimeout    time.Duration // per-repo wall-clock limit (0 = unlimited)
	NoHistory      bool
	Verbose        bool
	DumpDir        string
	DumpHeadOnly   bool      // dump only the HEAD tree of each branch (no commit history, no symlinks)
	LootDir        string    // if set, save full file content for any file that produces a finding
	NoFPReduction  bool      // disable false-positive filter
	IncludeContent bool      // embed full file text in JSON findings
	ErrWriter      io.Writer // destination for user-facing error messages (defaults to os.Stderr)

	packs         []*Pack
	seenBlobs     sync.Map // sha  -> struct{}: prevents scanning same content twice
	seenCommit    sync.Map // sha  -> struct{}: prevents re-walking commits
	seenTree      sync.Map // sha  -> struct{}: prevents re-walking the same tree across commits
	seenPaths     sync.Map // path -> struct{}: ensures only the HEAD-state of a path is dumped
	seenLootBlobs sync.Map // blob sha -> struct{}: prevents writing identical content twice
	dumpCount     atomic.Int64

	// Loose-object reachability tracking for early abort.
	// When no pack files are available and every loose-object fetch returns 404,
	// the repo is inaccessible — abort rather than hammering a dead server.
	looseFound    atomic.Int64
	looseNotFound atomic.Int64

	// Blob-specific reachability tracking.
	// Trees may succeed (revealing file paths) while blobs are blocked.
	// If all blob fetches return 404, there is nothing to scan — abort.
	blobFound    atomic.Int64
	blobNotFound atomic.Int64

	// BlobsProcessed is exported for status-bar reporting.
	BlobsProcessed atomic.Int64

	// Tree-specific reachability tracking.
	// Commit objects may be accessible while tree/blob objects are blocked
	// (e.g. objects/ served only for specific types via server config).
	// If trees consistently return 404, abort before walking the whole history.
	treeFound    atomic.Int64
	treeNotFound atomic.Int64

	scanCancel    func() // cancels this repo's internal scan context
	indexOnlyMode bool   // true when objects are inaccessible and only .git/index is used
}

func (r *RepoScanner) logf(format string, args ...any) {
	if r.Verbose {
		log.Printf("[%s] "+format, append([]any{r.URL}, args...)...)
	}
}

// errf always prints to stderr regardless of verbose setting.
func (r *RepoScanner) errf(format string, args ...any) {
	w := r.ErrWriter
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintf(w, "[%s] "+format+"\n", append([]any{r.URL}, args...)...)
}

func (r *RepoScanner) getURL(ctx context.Context, path string) ([]byte, error) {
	u := strings.TrimRight(r.URL, "/") + "/" + strings.TrimLeft(path, "/")
	return r.Client.Get(ctx, u)
}

// Scan discovers refs, loads pack files, walks the object graph, and returns findings.
func (r *RepoScanner) Scan(ctx context.Context, rules []scan.Rule) ([]scan.Finding, error) {
	// scanCtx lets us abort this repo's scan independently of other repos.
	// An optional ScanTimeout caps the per-repo wall-clock time.
	var scanCtx context.Context
	var scanCancel context.CancelFunc
	if r.ScanTimeout > 0 {
		scanCtx, scanCancel = context.WithTimeout(ctx, r.ScanTimeout)
	} else {
		scanCtx, scanCancel = context.WithCancel(ctx)
	}
	defer scanCancel()
	r.scanCancel = scanCancel

	refs, namedRefs, err := r.discoverRefs(scanCtx)
	if err != nil {
		return nil, fmt.Errorf("ref discovery: %w", err)
	}
	r.logf("discovered %d ref(s), %d named", len(refs), len(namedRefs))

	if err := r.loadPacks(scanCtx); err != nil {
		// Not fatal: loose objects may still be accessible.
		r.logf("pack loading: %v", err)
	}

	// Viability probe: if there are no pack files, check whether loose objects
	// are reachable at all.  Fail fast rather than attempting thousands of 404s.
	//
	// If the standard probe fails, try fetching .git/index as a fallback.  Some
	// servers expose the index and individual blob loose objects but block tree and
	// commit objects (or omit objects/info/packs).  In that case we can still scan
	// and dump the current working tree via dispatchIndexEntries.
	if len(r.packs) == 0 && !r.probeObjectsAccessible(scanCtx, refs) {
		if indexData, err := r.getURL(scanCtx, "index"); err == nil {
			if entries, err2 := ParseGitIndex(indexData); err2 == nil && len(entries) > 0 {
				r.logf("falling back to index-only mode (%d entries)", len(entries))
				r.indexOnlyMode = true
			}
		}
		if !r.indexOnlyMode {
			return nil, fmt.Errorf("objects not accessible (no packs and loose objects return 404) — skipping")
		}
	}

	dumpBase := ""
	if r.DumpDir != "" {
		dumpBase = filepath.Join(r.DumpDir, repoDirName(r.URL)+"-"+time.Now().Format("2006-01-02_15-04-05"))
		if err := os.MkdirAll(dumpBase, 0o755); err != nil {
			return nil, fmt.Errorf("create dump dir %s: %w", dumpBase, err)
		}
		r.errf("dumping to %s", dumpBase)
	}

	blobCh := make(chan blobJob, 256)
	findingCh := make(chan scan.Finding, 256)

	var blobWG sync.WaitGroup
	for i := 0; i < r.BlobWorkers; i++ {
		blobWG.Add(1)
		go func() {
			defer blobWG.Done()
			for job := range blobCh {
				if scanCtx.Err() != nil {
					return
				}
				r.processBlob(scanCtx, job, dumpBase, rules, findingCh)
			}
		}()
	}

	var findings []scan.Finding
	var collectWG sync.WaitGroup
	collectWG.Add(1)
	go func() {
		defer collectWG.Done()
		// In no-history mode, deduplicate findings by (rule, path, line text).
		// The same secret can appear in many commits with slightly different blob
		// SHAs (file changed elsewhere), so seenBlobs alone doesn't prevent it.
		var seenFindings map[string]bool
		if r.NoHistory {
			seenFindings = make(map[string]bool)
		}
		for f := range findingCh {
			if seenFindings != nil {
				key := f.RuleName + "\x00" + f.FilePath + "\x00" + f.Line
				if seenFindings[key] {
					continue
				}
				seenFindings[key] = true
			}
			findings = append(findings, f)
		}
	}()

	// Optionally cap the number of starting refs (useful for mass scanning).
	walkrefs := refs
	if r.MaxRefs > 0 && len(walkrefs) > r.MaxRefs {
		walkrefs = walkrefs[:r.MaxRefs]
	}

	// Phase A: Dispatch the current working tree from .git/index.
	// This runs before the commit walk so blob objects are fetched (and looseFound
	// incremented) before tree-object 404s from the commit walk could trip the
	// abort threshold.  It is also the only source of blob SHAs when tree objects
	// are not accessible as loose files.
	r.dispatchIndexEntries(scanCtx, blobCh)

	// Phase B: Walk refs concurrently — each ref is an independent starting point and
	// seenCommit/seenTree dedup prevents redundant fetches across walkers.
	// Skipped in index-only mode (tree/commit objects not accessible).
	var walkWG sync.WaitGroup
	if !r.indexOnlyMode {
		walkSem := make(chan struct{}, r.BlobWorkers)
		for _, commitSHA := range walkrefs {
			select {
			case <-scanCtx.Done():
				goto doneWalking
			case walkSem <- struct{}{}:
			}
			walkWG.Add(1)
			go func(sha string) {
				defer walkWG.Done()
				defer func() { <-walkSem }()
				r.walkCommits(scanCtx, sha, blobCh)
			}(commitSHA)
		}
	}
doneWalking:
	walkWG.Wait()

	// Phase C: Per-branch dumps — walk the root tree of each named branch and
	// write files to <dumpBase>/<branchName>/.  Runs after the main scan walk
	// so scan dedup (seenBlobs) is already populated and needScan=false for all
	// branch-dump jobs (avoiding redundant secret scans).
	if dumpBase != "" && len(namedRefs) > 0 && !r.indexOnlyMode {
		r.dumpBranches(scanCtx, namedRefs, dumpBase, blobCh)
	}

	close(blobCh)
	blobWG.Wait()
	close(findingCh)
	collectWG.Wait()

	if dumpBase != "" {
		r.errf("dumped %d file(s) to %s", r.dumpCount.Load(), dumpBase)
	}
	if r.indexOnlyMode && r.blobFound.Load() == 0 && r.blobNotFound.Load() > 0 {
		r.errf("note: index parsed (%d paths) but all blob objects returned 404 — content is likely in an inaccessible pack file; path-rule findings only", r.blobNotFound.Load())
	}

	if ctx.Err() != nil {
		return findings, ctx.Err()
	}
	return findings, nil
}

// processBlob fetches a blob, optionally writes it to disk, and scans for secrets.
func (r *RepoScanner) processBlob(ctx context.Context, job blobJob, dumpBase string, rules []scan.Rule, findingCh chan<- scan.Finding) {
	// Path scan runs first — before the blob fetch — so interesting-file findings
	// are emitted even when blob content is inaccessible (e.g. objects in blocked
	// pack files that were discovered via .git/index).
	var anyFindings bool
	if job.needScan {
		for _, m := range scan.ScanPath(rules, job.path) {
			findingCh <- scan.Finding{
				RepoURL:    r.URL,
				CommitHash: job.commitHash,
				FilePath:   job.path,
				LineNum:    0,
				Line:       m.Text,
				RuleName:   m.RuleName,
				RuleDesc:   m.RuleDesc,
				Severity:   m.Severity,
				Group:      m.Group,
				Tags:       m.Tags,
			}
			anyFindings = true
		}
	}

	obj, err := r.fetchObject(ctx, job.sha)
	if err != nil {
		r.logf("fetch %s (%s): %v", job.path, job.sha[:8], err)
		// Index-sourced jobs are excluded from the abort counter: their SHAs come
		// from .git/index which reliably reflects the working tree, but when many
		// blobs live in an inaccessible pack the high miss rate would otherwise
		// trigger a premature abort before useful index content is processed.
		if errors.Is(err, fetch.ErrNotFound) && !job.fromIndex {
			notFound := r.blobNotFound.Add(1)
			found := r.blobFound.Load()
			// Abort when the vast majority of blob fetches fail — objects are blocked.
			// Require at least 30 attempts and a >95% miss rate before aborting so that
			// partially-accessible repos (a few blobs reachable) are still scanned.
			if notFound >= 30 && found*20 < notFound && r.scanCancel != nil {
				r.errf("aborting: blob 404 rate >95%% (%d misses, %d hits) — files appear blocked", notFound, found)
				r.scanCancel()
			}
		}
		if errors.Is(err, fetch.ErrNotFound) && job.fromIndex {
			// Track index blob misses separately so we can warn at the end.
			r.blobNotFound.Add(1)
		}
		return
	}
	if obj.Type != ObjBlob {
		return
	}
	r.blobFound.Add(1)
	r.BlobsProcessed.Add(1)
	data := obj.Data

	// Dump: write this path to disk (no size/binary filter — dump everything).
	effectiveDump := dumpBase
	if job.dumpDir != "" {
		effectiveDump = job.dumpDir
	}
	if job.needDump && effectiveDump != "" {
		r.dumpBlob(effectiveDump, job.path, data)
	}

	// Content scan: check file bytes for secret patterns.
	if job.needScan {
		if r.MaxBlobSize > 0 && int64(len(data)) > r.MaxBlobSize {
			return
		}
		if isBinary(data) {
			return
		}
		var fileContent string
		if r.IncludeContent {
			fileContent = string(data)
		}
		for _, m := range scan.ScanContent(rules, data, r.NoFPReduction, job.path) {
			findingCh <- scan.Finding{
				RepoURL:     r.URL,
				CommitHash:  job.commitHash,
				FilePath:    job.path,
				LineNum:     m.Line,
				Line:        m.Text,
				RuleName:    m.RuleName,
				RuleDesc:    m.RuleDesc,
				Severity:    m.Severity,
				Group:       m.Group,
				Tags:        m.Tags,
				FileContent: fileContent,
			}
			anyFindings = true
		}
	}

	// Loot: save the full file to <LootDir>/<host>/<commit>/<path> when any finding
	// was produced. Keyed by blob SHA so identical content is only written once.
	if anyFindings && r.LootDir != "" {
		r.saveLoot(job.sha, job.commitHash, job.path, data)
	}
}

// saveLoot writes the file content to <LootDir>/<host>/<commit[:8]>/<path>.
// Deduped by blob SHA — identical content (same SHA) is only written once even
// if the same blob appears in multiple commits.
func (r *RepoScanner) saveLoot(blobSHA, commitHash, path string, data []byte) {
	if _, loaded := r.seenLootBlobs.LoadOrStore(blobSHA, struct{}{}); loaded {
		return
	}
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		return
	}
	shortCommit := commitHash
	if len(shortCommit) > 8 {
		shortCommit = shortCommit[:8]
	}
	dest := filepath.Join(r.LootDir, repoDirName(r.URL), shortCommit, cleaned)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		r.errf("loot mkdir %s: %v", filepath.Dir(dest), err)
		return
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		r.errf("loot write %s: %v", dest, err)
	}
}

// dumpBlob writes data to <dumpBase>/<path>, creating parent directories as needed.
// Git trees can contain both a blob at "foo" and blobs under "foo/bar/…", which is
// impossible to represent on disk. When a path component already exists as a regular
// file we remove it so MkdirAll can create the directory in its place.
func (r *RepoScanner) dumpBlob(dumpBase, path string, data []byte) {
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) || strings.HasPrefix(cleaned, "..") {
		r.errf("dump: skipping unsafe path %q", path)
		return
	}
	dest := filepath.Join(dumpBase, cleaned)

	// Ensure every ancestor directory exists. Walk each prefix; if it exists as
	// a regular file, remove it so it can become a directory instead.
	parts := strings.Split(filepath.ToSlash(cleaned), "/")
	for i := 1; i < len(parts); i++ {
		ancestor := filepath.Join(dumpBase, filepath.Join(parts[:i]...))
		if fi, err := os.Lstat(ancestor); err == nil && !fi.IsDir() {
			os.Remove(ancestor) // ignore error; MkdirAll will surface it if needed
		}
	}

	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		r.errf("dump mkdir %s: %v", filepath.Dir(dest), err)
		return
	}
	// If dest itself is already a directory (reverse conflict: dir before file),
	// we cannot overwrite it — skip silently.
	if fi, err := os.Lstat(dest); err == nil && fi.IsDir() {
		return
	}
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		r.errf("dump write %s: %v", dest, err)
		return
	}
	r.dumpCount.Add(1)
	r.logf("dump: wrote %s", dest)
}

// changedBlob is a blob that was added or modified relative to a parent tree.
type changedBlob struct {
	sha  string
	path string
}

// diffTrees collects blobs present in newTreeSHA that are absent or have a
// different SHA in oldTreeSHA. Pass oldTreeSHA="" to treat all blobs as new
// (used for the initial commit which has no parent).
func (r *RepoScanner) diffTrees(ctx context.Context, oldTreeSHA, newTreeSHA, prefix string, out *[]changedBlob) {
	if ctx.Err() != nil || newTreeSHA == "" {
		return
	}
	// Identical tree objects — nothing changed in this subtree.
	if oldTreeSHA == newTreeSHA {
		return
	}

	var oldEntries []TreeEntry
	if oldTreeSHA != "" {
		if obj, err := r.fetchObject(ctx, oldTreeSHA); err == nil && obj.Type == ObjTree {
			oldEntries, _ = ParseTree(obj.Data)
		}
	}

	obj, err := r.fetchObject(ctx, newTreeSHA)
	if err != nil || obj.Type != ObjTree {
		return
	}
	newEntries, err := ParseTree(obj.Data)
	if err != nil {
		return
	}

	oldMap := make(map[string]TreeEntry, len(oldEntries))
	for _, e := range oldEntries {
		oldMap[e.Name] = e
	}

	for _, ne := range newEntries {
		if ctx.Err() != nil {
			return
		}
		fullPath := prefix + ne.Name
		old, existed := oldMap[ne.Name]
		if ne.IsTree {
			var oldSubSHA string
			if existed && old.IsTree {
				oldSubSHA = old.SHA
			}
			r.diffTrees(ctx, oldSubSHA, ne.SHA, fullPath+"/", out)
		} else if !existed || old.SHA != ne.SHA {
			*out = append(*out, changedBlob{sha: ne.SHA, path: fullPath})
		}
	}
}

// dumpBranchHead dumps the complete tree at the HEAD commit of ref into destDir/,
// with files written flat (no per-commit subdirectories).
// Used by DumpHeadOnly mode.
func (r *RepoScanner) dumpBranchHead(ctx context.Context, ref Ref, destDir string, blobCh chan<- blobJob) {
	obj, err := r.fetchObject(ctx, ref.SHA)
	if err != nil {
		return
	}
	if obj.Type == ObjTag {
		tag, err := ParseTag(obj.Data)
		if err != nil {
			return
		}
		obj, err = r.fetchObject(ctx, tag.Object)
		if err != nil || obj.Type != ObjCommit {
			return
		}
	}
	if obj.Type != ObjCommit {
		return
	}
	commit, err := ParseCommit(obj.Data)
	if err != nil {
		return
	}
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		r.errf("dump branch head dir %s: %v", destDir, err)
		return
	}
	// Pass empty oldTreeSHA so diffTrees returns every blob in the tree.
	var allFiles []changedBlob
	r.diffTrees(ctx, "", commit.Tree, "", &allFiles)
	for _, b := range allFiles {
		select {
		case blobCh <- blobJob{
			sha:       b.sha,
			path:      b.path,
			needScan:  false,
			needDump:  true,
			dumpDir:   destDir,
			fromIndex: true,
		}:
		case <-ctx.Done():
			return
		}
	}
}

// dumpBranches walks the commit history of each named ref and dumps, for each
// commit, only the files that changed relative to its first parent.  Files are
// written to <dumpBase>/<branchName>/<commitSHA>/<path>.
//
// A per-branch seenPaths map ensures each file path is written at most once —
// the first (most recent) commit that introduced or changed it wins.  Walking
// proceeds newest→oldest so the HEAD version is always the one kept.
func (r *RepoScanner) dumpBranches(ctx context.Context, namedRefs []Ref, dumpBase string, blobCh chan<- blobJob) {
	commitsDir := filepath.Join(dumpBase, "commits")
	for _, ref := range namedRefs {
		if ctx.Err() != nil {
			return
		}
		branchDir := filepath.Join(dumpBase, SanitizeName(ref.Name))
		r.logf("dumping branch %q to %s", ref.Name, branchDir)

		// Head-only mode: dump the complete tree at HEAD directly into branchDir/,
		// no per-commit subdirectories, no commits/ dir, no symlinks.
		if r.DumpHeadOnly {
			r.dumpBranchHead(ctx, ref, branchDir, blobCh)
			continue
		}

		seenPaths := make(map[string]bool)
		seenCommit := make(map[string]bool)
		queue := []string{ref.SHA}

		for len(queue) > 0 {
			if ctx.Err() != nil {
				break
			}
			sha := queue[0]
			queue = queue[1:]
			if seenCommit[sha] {
				continue
			}
			seenCommit[sha] = true

			obj, err := r.fetchObject(ctx, sha)
			if err != nil {
				continue
			}
			if obj.Type == ObjTag {
				tag, err := ParseTag(obj.Data)
				if err == nil {
					queue = append(queue, tag.Object)
				}
				continue
			}
			if obj.Type != ObjCommit {
				continue
			}
			commit, err := ParseCommit(obj.Data)
			if err != nil {
				continue
			}

			// Resolve the first parent's tree for diffing (merge commits use first parent).
			var parentTreeSHA string
			if len(commit.Parents) > 0 {
				if pobj, err := r.fetchObject(ctx, commit.Parents[0]); err == nil && pobj.Type == ObjCommit {
					if pcommit, err := ParseCommit(pobj.Data); err == nil {
						parentTreeSHA = pcommit.Tree
					}
				}
			}

			var changed []changedBlob
			r.diffTrees(ctx, parentTreeSHA, commit.Tree, "", &changed)

			// Keep only paths not yet written (newest-first means HEAD version wins).
			var toDump []changedBlob
			for _, b := range changed {
				if !seenPaths[b.path] {
					seenPaths[b.path] = true
					toDump = append(toDump, b)
				}
			}

			if len(toDump) > 0 {
				commitDir := filepath.Join(commitsDir, sha)
				if err := os.MkdirAll(commitDir, 0o755); err != nil {
					r.errf("dump commit dir %s: %v", commitDir, err)
				} else {
					for _, b := range toDump {
						select {
						case blobCh <- blobJob{
							sha:       b.sha,
							path:      b.path,
							needScan:  false,
							needDump:  true,
							dumpDir:   commitDir,
							fromIndex: true,
						}:
						case <-ctx.Done():
							return
						}
						// Create a branch-level symlink so the branch directory
						// looks like a single unified tree. Commits live under
						// <dumpBase>/commits/<sha>/ so symlinks go up one extra
						// level compared to the old in-branch commit dirs:
						//   depth=0 (root file):  ../commits/<sha>/file
						//   depth=1 (one subdir):  ../../commits/<sha>/dir/file
						parts := strings.Split(b.path, "/")
						for i := 1; i < len(parts); i++ {
							anc := filepath.Join(branchDir, filepath.Join(parts[:i]...))
							if fi, err := os.Lstat(anc); err == nil && !fi.IsDir() {
								os.Remove(anc)
							}
						}
						symlinkPath := filepath.Join(branchDir, filepath.FromSlash(b.path))
						if err := os.MkdirAll(filepath.Dir(symlinkPath), 0o755); err == nil {
							depth := strings.Count(b.path, "/")
							relTarget := strings.Repeat("../", depth+1) + "commits/" + sha + "/" + b.path
							os.Symlink(relTarget, symlinkPath)
						}
					}
				}
			}

			if !r.NoHistory {
				queue = append(queue, commit.Parents...)
			}
		}
	}
}

// dispatchIndexEntries fetches .git/index, parses it, and dispatches a blobJob
// for every entry whose SHA has not already been queued.  It uses the same
// seenBlobs / seenPaths deduplication as walkTree so entries found by both
// paths are not fetched twice.
func (r *RepoScanner) dispatchIndexEntries(ctx context.Context, blobCh chan<- blobJob) {
	data, err := r.getURL(ctx, "index")
	if err != nil {
		return
	}
	entries, err := ParseGitIndex(data)
	if err != nil {
		r.logf("dispatchIndexEntries: parse error: %v", err)
		return
	}
	r.logf("dispatchIndexEntries: %d entries from .git/index", len(entries))

	for _, e := range entries {
		if ctx.Err() != nil {
			return
		}
		_, blobSeen := r.seenBlobs.LoadOrStore(e.SHA, struct{}{})
		needScan := !blobSeen

		// Only dump index entries in index-only mode (no commit history to walk).
		// In normal mode, dumpBranches handles all file dumping per commit.
		needDump := false
		if r.DumpDir != "" && r.indexOnlyMode {
			_, pathSeen := r.seenPaths.LoadOrStore(e.Path, struct{}{})
			needDump = !pathSeen
		}

		if !needScan && !needDump {
			continue
		}

		select {
		case blobCh <- blobJob{
			sha:        e.SHA,
			path:       e.Path,
			commitHash: "index",
			needScan:   needScan,
			needDump:   needDump,
			fromIndex:  true,
		}:
		case <-ctx.Done():
			return
		}
	}
}

// walkCommits does a BFS from startSHA, queuing blob jobs for every file seen.
func (r *RepoScanner) walkCommits(ctx context.Context, startSHA string, blobCh chan<- blobJob) {
	queue := []string{startSHA}
	for len(queue) > 0 {
		if ctx.Err() != nil {
			return
		}
		sha := queue[0]
		queue = queue[1:]

		if _, seen := r.seenCommit.LoadOrStore(sha, struct{}{}); seen {
			continue
		}

		obj, err := r.fetchObject(ctx, sha)
		if err != nil {
			r.logf("fetch commit %s: %v", sha[:8], err)
			continue
		}

		switch obj.Type {
		case ObjTag:
			tag, err := ParseTag(obj.Data)
			if err == nil && isValidSHA(tag.Object) {
				queue = append(queue, tag.Object)
			}
		case ObjCommit:
			commit, err := ParseCommit(obj.Data)
			if err != nil {
				r.logf("parse commit %s: %v", sha[:8], err)
				continue
			}
			r.walkTree(ctx, commit.Tree, "", sha, blobCh)
			if !r.NoHistory {
				queue = append(queue, commit.Parents...)
			}
		default:
			r.logf("unexpected type %s for %s", ObjTypeName(obj.Type), sha[:8])
		}
	}
}

// walkTree recursively walks a git tree, sending blobJob entries to blobCh.
//
// needScan and needDump are determined independently:
//   - needScan: true only the first time a blob SHA is encountered (dedup by content)
//   - needDump: true only the first time a path is encountered (BFS order means HEAD wins)
//
// This ensures every file path is dumped exactly once, even when multiple paths share
// the same content (same SHA) — which the old seenBlobs-only gate would silently skip.
func (r *RepoScanner) walkTree(ctx context.Context, treeSHA, pathPrefix, commitSHA string, blobCh chan<- blobJob) {
	if ctx.Err() != nil {
		return
	}

	// Skip trees we've already walked — same SHA means identical content.
	// This avoids re-fetching shared subtrees across commits (e.g. an unchanged
	// vendor/ directory shared by 50 consecutive commits).
	if _, seen := r.seenTree.LoadOrStore(treeSHA, struct{}{}); seen {
		return
	}

	obj, err := r.fetchObject(ctx, treeSHA)
	if err != nil {
		r.logf("fetch tree %s: %v", treeSHA[:8], err)
		if errors.Is(err, fetch.ErrNotFound) {
			notFound := r.treeNotFound.Add(1)
			found := r.treeFound.Load()
			// Abort when trees are consistently inaccessible — commits may be
			// accessible while tree/blob objects are blocked.  Use a low
			// threshold (10) because trees fail in bursts (concurrent walkers).
			if notFound >= 10 && found*20 < notFound && r.scanCancel != nil {
				r.errf("aborting: tree 404 rate >95%% (%d misses, %d hits) — objects appear blocked", notFound, found)
				r.scanCancel()
			}
		}
		return
	}
	r.treeFound.Add(1)
	if obj.Type != ObjTree {
		return
	}

	entries, err := ParseTree(obj.Data)
	if err != nil {
		r.logf("parse tree %s: %v", treeSHA[:8], err)
		return
	}

	for _, entry := range entries {
		fullPath := pathPrefix + entry.Name
		if entry.IsTree {
			r.walkTree(ctx, entry.SHA, fullPath+"/", commitSHA, blobCh)
			continue
		}

		// needScan: first time this exact content (SHA) is seen.
		_, blobSeen := r.seenBlobs.LoadOrStore(entry.SHA, struct{}{})
		needScan := !blobSeen

		if !needScan {
			continue
		}

		select {
		case blobCh <- blobJob{
			sha:        entry.SHA,
			path:       fullPath,
			commitHash: commitSHA,
			needScan:   needScan,
		}:
		case <-ctx.Done():
			return
		}
	}
}

// fetchObject retrieves a git object by SHA from loaded packs, falling back to loose files.
func (r *RepoScanner) fetchObject(ctx context.Context, sha string) (*Object, error) {
	for _, p := range r.packs {
		if p.HasObject(sha) {
			return p.GetObject(sha)
		}
	}
	// Loose-object fetch — track 404s to detect inaccessible repos.
	path := "objects/" + sha[:2] + "/" + sha[2:]
	data, err := r.getURL(ctx, path)
	if err != nil {
		if errors.Is(err, fetch.ErrNotFound) && !r.indexOnlyMode {
			notFound := r.looseNotFound.Add(1)
			// Abort after 30 misses with zero successes — objects are unreachable.
			// Skip in index-only mode: we already know objects are inaccessible.
			if notFound >= 30 && r.looseFound.Load() == 0 && r.scanCancel != nil {
				r.errf("aborting: %d consecutive object 404s with no successful fetches — objects appear blocked", notFound)
				r.scanCancel()
			}
		}
		return nil, err
	}
	r.looseFound.Add(1)
	return ParseLooseObject(data)
}

// probeObjectsAccessible checks whether at least one of the given SHAs can be fetched
// as a loose object.  Probes run concurrently and the function returns as soon as any
// one succeeds.  Used to fail-fast on repos where .git is exposed but objects/ is blocked.
func (r *RepoScanner) probeObjectsAccessible(ctx context.Context, refs []string) bool {
	probe := refs
	if len(probe) > 5 {
		probe = refs[:5]
	}

	probeCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct{ ok bool }
	ch := make(chan result, len(probe))

	for _, sha := range probe {
		go func(s string) {
			_, err := r.fetchObject(probeCtx, s)
			if err == nil {
				ch <- result{true}
			} else if !errors.Is(err, fetch.ErrNotFound) {
				ch <- result{true} // non-404 error — inconclusive, let the scan try
			} else {
				ch <- result{false}
			}
		}(sha)
	}

	for range probe {
		if r := <-ch; r.ok {
			return true
		}
	}
	return false
}

// ── Ref discovery ─────────────────────────────────────────────────────────────

var shaRE = regexp.MustCompile(`\b([0-9a-f]{40})\b`)

// packSHARE extracts pack SHAs from an Apache/nginx directory listing.
// Matches hrefs like: pack-<sha>.pack or pack-<sha>.idx
var packSHARE = regexp.MustCompile(`pack-([0-9a-f]{40})\.(?:pack|idx)`)

var branchConfigRE = regexp.MustCompile(`(?m)^\[branch\s+"([^"]+)"\]`)

// infoRefsRE parses lines from .git/info/refs: "<sha>\t<refname>"
var infoRefsRE = regexp.MustCompile(`(?m)^([0-9a-f]{40})\t(refs/[^\s\r\n]+)`)

// packedRefsRE parses lines from .git/packed-refs: "<sha> <refname>"
var packedRefsRE = regexp.MustCompile(`(?m)^([0-9a-f]{40}) (refs/[^\s\r\n]+)`)

// refShortName converts a full ref name to a short branch/tag name, or returns "".
// Strips refs/heads/, refs/tags/, and refs/remotes/origin/ prefixes.
func refShortName(fullRef string) string {
	for _, prefix := range []string{"refs/heads/", "refs/tags/", "refs/remotes/origin/"} {
		if strings.HasPrefix(fullRef, prefix) {
			if name := strings.TrimPrefix(fullRef, prefix); name != "" {
				return name
			}
		}
	}
	return ""
}

// discoverRefs returns all unique object SHAs and named refs (branch/tag → SHA)
// found across every available source. Requests are issued concurrently.
func (r *RepoScanner) discoverRefs(ctx context.Context) ([]string, []Ref, error) {
	var mu sync.Mutex
	seen := make(map[string]bool)
	namedSHAs := make(map[string]string) // shortName → sha (first-seen wins)

	add := func(sha string) {
		sha = strings.TrimSpace(strings.ToLower(sha))
		if !isValidSHA(sha) {
			return
		}
		mu.Lock()
		seen[sha] = true
		mu.Unlock()
	}
	// addNamed records both the SHA and its branch/tag short-name mapping.
	addNamed := func(fullRef, sha string) {
		sha = strings.TrimSpace(strings.ToLower(sha))
		if !isValidSHA(sha) {
			return
		}
		short := refShortName(fullRef)
		mu.Lock()
		seen[sha] = true
		if short != "" {
			if _, exists := namedSHAs[short]; !exists {
				namedSHAs[short] = sha
			}
		}
		mu.Unlock()
	}
	addAll := func(data []byte) {
		for _, m := range shaRE.FindAll(data, -1) {
			add(string(m))
		}
	}
	fetchAndAddAll := func(path string) {
		if data, err := r.getURL(ctx, path); err == nil {
			addAll(data)
		}
	}

	commonBranches := []string{
		"main", "master", "develop", "development", "dev",
		"staging", "stage", "production", "prod", "release",
		"trunk", "next", "edge", "canary", "hotfix", "test", "qa",
	}

	// Phase 1: HEAD (two sequential fetches — second depends on first)
	if data, err := r.getURL(ctx, "HEAD"); err == nil {
		line := strings.TrimSpace(string(data))
		if strings.HasPrefix(line, "ref: ") {
			refPath := strings.TrimPrefix(line, "ref: ")
			if refData, err := r.getURL(ctx, refPath); err == nil {
				addNamed(refPath, strings.TrimSpace(string(refData)))
			}
		} else {
			add(line)
		}
	}

	// Phase 2: Fetch all static paths + config in parallel.
	// info/refs and packed-refs are handled explicitly (need named-ref parsing).
	// commonBranches refs are fetched individually so addNamed can record them.
	staticPaths := []string{
		"FETCH_HEAD", "ORIG_HEAD", "MERGE_HEAD",
		"CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_HEAD", "refs/stash",
	}

	var wg sync.WaitGroup
	var configData []byte
	wg.Add(1)
	go func() {
		defer wg.Done()
		if data, err := r.getURL(ctx, "config"); err == nil {
			mu.Lock()
			configData = data
			mu.Unlock()
		}
	}()
	// info/refs
	wg.Add(1)
	go func() {
		defer wg.Done()
		if data, err := r.getURL(ctx, "info/refs"); err == nil {
			addAll(data)
			for _, m := range infoRefsRE.FindAllSubmatch(data, -1) {
				addNamed(string(m[2]), string(m[1]))
			}
		}
	}()
	// packed-refs
	wg.Add(1)
	go func() {
		defer wg.Done()
		if data, err := r.getURL(ctx, "packed-refs"); err == nil {
			for _, m := range packedRefsRE.FindAllSubmatch(data, -1) {
				ref := string(m[2])
				if !strings.HasSuffix(ref, "^{}") { // skip peeled tag entries
					addNamed(ref, string(m[1]))
				}
			}
		}
	}()
	for _, path := range staticPaths {
		wg.Add(1)
		go func(p string) {
			defer wg.Done()
			fetchAndAddAll(p)
		}(path)
	}
	// Fetch common branch refs — both refs/heads/ and refs/remotes/origin/
	for _, b := range commonBranches {
		for _, prefix := range []string{"refs/heads/", "refs/remotes/origin/"} {
			wg.Add(1)
			go func(fullRef string) {
				defer wg.Done()
				if data, err := r.getURL(ctx, fullRef); err == nil {
					addNamed(fullRef, strings.TrimSpace(string(data)))
				}
			}(prefix + b)
		}
	}
	wg.Wait()

	// Phase 3: Use config to discover additional branch refs.
	var configBranches []string
	if configData != nil {
		r.logf("fetched git config (%d bytes)", len(configData))
		configBranches = parseBranchNamesFromConfig(configData)
	}

	// Phase 4: Config-dependent branch refs + all reflogs in parallel.
	// Reflogs are skipped in no-history mode — they contain every SHA the branch
	// has ever pointed to and would cause every historical commit to be scanned
	// even though parent-walking is disabled.
	for _, name := range configBranches {
		wg.Add(1)
		go func(n string) {
			defer wg.Done()
			if data, err := r.getURL(ctx, "refs/heads/"+n); err == nil {
				addNamed("refs/heads/"+n, strings.TrimSpace(string(data)))
			}
		}(name)
	}
	if !r.NoHistory {
		reflogPaths := []string{"logs/HEAD"}
		for _, b := range append(commonBranches, configBranches...) {
			reflogPaths = append(reflogPaths, "logs/refs/heads/"+b)
		}
		for _, path := range reflogPaths {
			wg.Add(1)
			go func(p string) {
				defer wg.Done()
				if data, err := r.getURL(ctx, p); err == nil {
					before := func() int { mu.Lock(); defer mu.Unlock(); return len(seen) }()
					addAll(data)
					after := func() int { mu.Lock(); defer mu.Unlock(); return len(seen) }()
					r.logf("reflog %s: +%d SHA(s)", p, after-before)
				}
			}(path)
		}
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	var shas []string
	for sha := range seen {
		shas = append(shas, sha)
	}
	if len(shas) == 0 {
		return nil, nil, fmt.Errorf("no refs found (try -v for details)")
	}
	var namedRefs []Ref
	for name, sha := range namedSHAs {
		namedRefs = append(namedRefs, Ref{Name: name, SHA: sha})
	}
	sort.Slice(namedRefs, func(i, j int) bool { return namedRefs[i].Name < namedRefs[j].Name })
	return shas, namedRefs, nil
}

func parseBranchNamesFromConfig(data []byte) []string {
	var names []string
	for _, m := range branchConfigRE.FindAllSubmatch(data, -1) {
		names = append(names, string(m[1]))
	}
	return names
}

// ── Pack loading ──────────────────────────────────────────────────────────────

func (r *RepoScanner) loadPacks(ctx context.Context) error {
	var packHashes []string

	// Primary: objects/info/packs (standard dumb-HTTP git protocol)
	if data, err := r.getURL(ctx, "objects/info/packs"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "P pack-") || !strings.HasSuffix(line, ".pack") {
				continue
			}
			ph := strings.TrimPrefix(strings.TrimSuffix(line, ".pack"), "P pack-")
			if isValidSHA(ph) {
				packHashes = append(packHashes, ph)
			}
		}
	} else {
		r.logf("objects/info/packs: %v — trying directory listing fallback", err)
	}

	// Fallback: scrape objects/pack/ directory listing.
	// Some servers have directory listing enabled but lack objects/info/packs
	// (e.g. Apache with autoindex on but git update-server-info never run).
	if len(packHashes) == 0 {
		if data, err := r.getURL(ctx, "objects/pack/"); err == nil {
			for _, m := range packSHARE.FindAllSubmatch(data, -1) {
				ph := string(m[1])
				if isValidSHA(ph) {
					packHashes = append(packHashes, ph)
					r.logf("found pack via directory listing: %s", ph[:8])
				}
			}
		}
	}

	if len(packHashes) == 0 {
		return fmt.Errorf("no pack files found (objects/info/packs unavailable and no directory listing)")
	}

	base := strings.TrimRight(r.URL, "/")
	for _, ph := range packHashes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		idxURL := base + "/objects/pack/pack-" + ph + ".idx"
		packURL := base + "/objects/pack/pack-" + ph + ".pack"

		if r.MaxPackSize > 0 {
			if size, err := r.Client.ContentLength(ctx, packURL); err == nil && size > r.MaxPackSize {
				r.errf("pack %s is %.1f MB > -max-pack limit, skipping", ph[:8], float64(size)/(1<<20))
				continue
			}
		}

		idxData, err := r.Client.Get(ctx, idxURL)
		if err != nil {
			r.errf("fetch pack index %s: %v", ph[:8], err)
			continue
		}
		idx, err := ParsePackIndex(idxData)
		if err != nil {
			r.errf("parse pack index %s: %v", ph[:8], err)
			continue
		}
		r.logf("pack %s: %d objects", ph[:8], len(idx.Entries))

		packData, err := r.Client.Get(ctx, packURL)
		if err != nil {
			r.errf("fetch pack %s: %v", ph[:8], err)
			continue
		}
		pack, err := NewPack(packData, idx)
		if err != nil {
			r.errf("parse pack %s: %v", ph[:8], err)
			continue
		}
		r.packs = append(r.packs, pack)
		r.errf("loaded pack %s (%d objects)", ph[:8], len(idx.Entries))
	}
	return nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isBinary(data []byte) bool {
	check := data
	if len(check) > 8000 {
		check = check[:8000]
	}
	return bytes.IndexByte(check, 0) >= 0
}

func isValidSHA(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func repoDirName(repoURL string) string {
	u, err := url.Parse(repoURL)
	if err != nil {
		return SanitizeName(repoURL)
	}
	host := u.Hostname()
	path := strings.TrimSuffix(strings.TrimSuffix(u.Path, "/.git"), ".git")
	path = strings.Trim(path, "/")
	if path == "" {
		return SanitizeName(host)
	}
	return SanitizeName(host + "_" + strings.ReplaceAll(path, "/", "_"))
}

// SanitizeName replaces characters that are not alphanumeric, dash, underscore,
// or dot with underscores so the result is safe to use as a filename component.
func SanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteRune('_')
		}
	}
	return b.String()
}
