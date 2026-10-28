package corpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa/fuzzing/calls"
)

const maxInitialResultSize = 64 * 1024

type initialResultWrite struct {
	done chan struct{}
	err  error
}

// InitialPropertyResult records a zero-call property failure and the inputs required to replay it.
// Version 1 binds compiled artifacts, evaluation configuration, committed state and block history.
type InitialPropertyResult struct {
	SchemaVersion       int                `json:"schemaVersion"`
	Kind                string             `json:"kind"`
	TestID              string             `json:"testId"`
	PropertySignature   string             `json:"propertySignature"`
	Address             common.Address     `json:"address"`
	ContractName        string             `json:"contractName"`
	ContractIdentity    common.Hash        `json:"contractIdentity"`
	Calls               calls.CallSequence `json:"calls"`
	ArtifactFingerprint common.Hash        `json:"artifactFingerprint"`
	ConfigFingerprint   common.Hash        `json:"configFingerprint"`
	StateRoot           common.Hash        `json:"stateRoot"`
	BlockFingerprint    common.Hash        `json:"blockFingerprint"`
	// FileName identifies the corpus record in diagnostics; it is never read from JSON.
	FileName string `json:"-"`
}

func (r InitialPropertyResult) validate() error {
	if r.SchemaVersion != 1 || r.Kind != "initialPropertyFailure" {
		return fmt.Errorf("unsupported initial result schemaVersion=%d kind=%q", r.SchemaVersion, r.Kind)
	}
	if r.TestID == "" || r.PropertySignature == "" || r.ContractName == "" {
		return fmt.Errorf("initial result is missing property identity")
	}
	if r.Calls == nil || len(r.Calls) != 0 {
		return fmt.Errorf("initial result requires an empty calls array")
	}
	for _, hash := range []common.Hash{r.ContractIdentity, r.ArtifactFingerprint, r.ConfigFingerprint, r.StateRoot, r.BlockFingerprint} {
		if hash == (common.Hash{}) {
			return fmt.Errorf("initial result is missing an input fingerprint")
		}
	}
	return nil
}

func (r InitialPropertyResult) encoded() ([]byte, string, error) {
	if err := r.validate(); err != nil {
		return nil, "", err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return nil, "", err
	}
	if len(b) > maxInitialResultSize {
		return nil, "", fmt.Errorf("initial result exceeds %d bytes", maxInitialResultSize)
	}
	digest := sha256.Sum256(b)
	return b, hex.EncodeToString(digest[:]) + ".json", nil
}

// InitialPropertyResults returns detached records, ordered by filename, without consuming them as mutation seeds.
func (c *Corpus) InitialPropertyResults() []InitialPropertyResult {
	cd := c.initialResults
	cd.filesLock.Lock()
	results := make([]InitialPropertyResult, len(cd.files))
	for i, file := range cd.files {
		results[i] = file.data
		results[i].Calls = calls.CallSequence{}
	}
	cd.filesLock.Unlock()
	sort.Slice(results, func(i, j int) bool { return results[i].FileName < results[j].FileName })
	return results
}

// SaveInitialPropertyResult immediately saves a validated record, including when coverage is disabled.
// An empty corpus directory retains the record only in memory.
func (c *Corpus) SaveInitialPropertyResult(result InitialPropertyResult) (err error) {
	b, name, err := result.encoded()
	if err != nil {
		return err
	}
	cd := c.initialResults
	cd.filesLock.Lock()
	if pending := c.initialWrites[name]; pending != nil {
		cd.filesLock.Unlock()
		<-pending.done
		return pending.err
	}
	pending := &initialResultWrite{done: make(chan struct{})}
	c.initialWrites[name] = pending
	cd.filesLock.Unlock()
	defer func() {
		cd.filesLock.Lock()
		pending.err = err
		delete(c.initialWrites, name)
		close(pending.done)
		cd.filesLock.Unlock()
	}()
	result.FileName, result.Calls = name, calls.CallSequence{}
	if dir := c.initialResults.path; dir != "" {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("create initial results directory: %w", err)
		}
		file, err := os.CreateTemp(dir, ".initial-*")
		if err != nil {
			return err
		}
		defer func() { _ = os.Remove(file.Name()) }()
		_, writeErr := file.Write(b)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return fmt.Errorf("write initial result %s: %w", name, writeErr)
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Rename(file.Name(), filepath.Join(dir, name)); err != nil {
			// Windows can reject a concurrent replacement of an identical published record.
			published, readErr := readInitialBytes(filepath.Join(dir, name))
			if readErr != nil || !bytes.Equal(published, b) {
				return fmt.Errorf("publish initial result %s: %w", name, err)
			}
		}
	}
	return c.initialResults.addFile(name, result)
}

func (c *Corpus) readInitialResults() error {
	entries, err := os.ReadDir(c.initialResults.path)
	if err != nil {
		if os.IsNotExist(err) {
			if _, statErr := os.Lstat(c.initialResults.path); os.IsNotExist(statErr) {
				return nil
			}
		}
		return fmt.Errorf("read initial results directory: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(c.initialResults.path, entry.Name())
		if err := c.readInitialResult(path); err != nil {
			return fmt.Errorf("initial result %s: %w", filepath.Base(path), err)
		}
	}
	return nil
}

func (c *Corpus) readInitialResult(path string) error {
	b, err := readInitialBytes(path)
	if err != nil {
		return err
	}
	var result InitialPropertyResult
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("unexpected data after initial result")
	}
	_, name, err := result.encoded()
	if err != nil {
		return err
	}
	if filepath.Base(path) != name {
		return fmt.Errorf("initial result filename does not match its digest")
	}
	result.FileName = name
	return c.initialResults.addFile(name, result)
}

func readInitialBytes(path string) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("initial result must be a regular file")
	}
	if info.Size() > maxInitialResultSize {
		return nil, fmt.Errorf("initial result exceeds %d bytes", maxInitialResultSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	openedInfo, statErr := file.Stat()
	if statErr != nil || !openedInfo.Mode().IsRegular() {
		_ = file.Close()
		if statErr != nil {
			return nil, statErr
		}
		return nil, fmt.Errorf("initial result must be a regular file")
	}
	b, readErr := io.ReadAll(io.LimitReader(file, maxInitialResultSize+1))
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if len(b) > maxInitialResultSize {
		return nil, fmt.Errorf("initial result exceeds %d bytes", maxInitialResultSize)
	}
	return b, nil
}
