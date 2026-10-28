package corpus

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/logging"
	"github.com/stretchr/testify/require"
)

func initialResultFixture() InitialPropertyResult {
	return InitialPropertyResult{
		SchemaVersion: 1, Kind: "initialPropertyFailure", TestID: "PROPERTY-C-p()",
		PropertySignature: "p()", ContractName: "C", Address: common.HexToAddress("0x1"),
		ContractIdentity: common.HexToHash("0x1"), ArtifactFingerprint: common.HexToHash("0x2"),
		ConfigFingerprint: common.HexToHash("0x3"), StateRoot: common.HexToHash("0x4"),
		BlockFingerprint: common.HexToHash("0x5"), Calls: calls.CallSequence{},
	}
}

func TestInitialResultsConcurrent(t *testing.T) {
	c, err := NewCorpus(t.TempDir())
	require.NoError(t, err)
	errors := make([]error, 8)
	var wg sync.WaitGroup
	for i := range errors {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors[i] = c.SaveInitialPropertyResult(initialResultFixture())
			_ = c.InitialPropertyResults()
		}()
	}
	wg.Wait()
	for _, err := range errors {
		require.NoError(t, err)
	}
	require.Len(t, c.InitialPropertyResults(), 1)
	reloaded, err := NewCorpus(c.storageDirectory)
	require.NoError(t, err)
	require.Len(t, reloaded.InitialPropertyResults(), 1)
}

func TestInitialResultsWriteError(t *testing.T) {
	path := t.TempDir()
	c, err := NewCorpus(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, "initial_results"), []byte("file, not directory"), 0600))
	require.Error(t, c.SaveInitialPropertyResult(initialResultFixture()))
	require.Empty(t, c.InitialPropertyResults())
	_, err = NewCorpus(path)
	require.Error(t, err, "an existing file must not be treated as a missing manifest directory")
}

func TestInitialResultsConcurrentError(t *testing.T) {
	path := t.TempDir()
	c, err := NewCorpus(path)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(path, "initial_results"), []byte("blocking file"), 0600))
	errors := make([]error, 8)
	var wg sync.WaitGroup
	for i := range errors {
		wg.Add(1)
		go func() { defer wg.Done(); errors[i] = c.SaveInitialPropertyResult(initialResultFixture()) }()
	}
	wg.Wait()
	for _, err := range errors {
		require.Error(t, err)
	}
	require.Empty(t, c.InitialPropertyResults())
	// An error must release ownership so that the next save can succeed.
	require.NoError(t, os.Remove(filepath.Join(path, "initial_results")))
	require.NoError(t, c.SaveInitialPropertyResult(initialResultFixture()))
	require.Len(t, c.InitialPropertyResults(), 1)
}

func TestInitialResultsLiteralPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus[1]")
	c, err := NewCorpus(path)
	require.NoError(t, err)
	require.NoError(t, c.SaveInitialPropertyResult(initialResultFixture()))
	reloaded, err := NewCorpus(path)
	require.NoError(t, err)
	require.Len(t, reloaded.InitialPropertyResults(), 1)
}

func TestInitialResultsCleaner(t *testing.T) {
	path := t.TempDir()
	c, err := NewCorpus(path)
	require.NoError(t, err)
	require.NoError(t, c.SaveInitialPropertyResult(initialResultFixture()))
	for _, dir := range []string{"call_sequences", "test_results"} {
		require.NoError(t, os.MkdirAll(filepath.Join(path, dir), 0700))
		require.NoError(t, os.WriteFile(filepath.Join(path, dir, "legacy.json"), []byte("[]"), 0600))
	}
	c, err = NewCorpus(path)
	require.NoError(t, err)
	ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer ch.Close()
	require.NoError(t, c.Initialize(ch, nil))
	result, err := NewCorpusCleaner(c, logging.GlobalLogger).Clean(context.Background(), ch, nil)
	require.NoError(t, err)
	require.Equal(t, 1, result.DeferredInitialResults)
	require.Len(t, c.InitialPropertyResults(), 1)
	for _, dir := range []string{"call_sequences", "test_results"} {
		require.FileExists(t, filepath.Join(path, dir, "legacy.json"))
	}
}

func TestInitialResultsStorage(t *testing.T) {
	for _, disk := range []bool{false, true} {
		t.Run(map[bool]string{false: "memory", true: "disk"}[disk], func(t *testing.T) {
			path := ""
			if disk {
				path = t.TempDir()
			}
			c, err := NewCorpus(path)
			require.NoError(t, err)
			r := initialResultFixture()
			require.NoError(t, c.SaveInitialPropertyResult(r))
			require.NoError(t, c.SaveInitialPropertyResult(r))
			r.TestID, r.PropertySignature = "PROPERTY-C-q()", "q()"
			require.NoError(t, c.SaveInitialPropertyResult(r))
			require.Len(t, c.InitialPropertyResults(), 2)
			a, b := c.CallSequenceEntryCount()
			require.Zero(t, a+b)
			if disk {
				files, err := filepath.Glob(filepath.Join(path, "initial_results", "*.json"))
				require.NoError(t, err)
				require.Len(t, files, 2)
				c, err = NewCorpus(path)
				require.NoError(t, err)
				require.Len(t, c.InitialPropertyResults(), 2)
			}
			results := c.InitialPropertyResults()
			results[0].TestID = "mutated"
			require.NotEqual(t, "mutated", c.InitialPropertyResults()[0].TestID)
			require.NotNil(t, results[1].Calls)
		})
	}
}

func TestInitialResultsRejectInvalid(t *testing.T) {
	for _, kind := range []string{"schema", "kind", "calls", "missing", "unknown", "truncated", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			r := initialResultFixture()
			switch kind {
			case "schema":
				r.SchemaVersion = 2
			case "kind":
				r.Kind = "other"
			case "calls":
				r.Calls = nil
			case "missing":
				r.TestID = ""
			}
			data, err := json.Marshal(r)
			require.NoError(t, err)
			switch kind {
			case "unknown":
				data = append(data[:len(data)-1], []byte(",\"extra\":1}")...)
			case "truncated":
				data = data[:len(data)-2]
			case "oversize":
				data = make([]byte, 65537)
			}
			path := t.TempDir()
			require.NoError(t, os.Mkdir(filepath.Join(path, "initial_results"), 0700))
			require.NoError(t, os.WriteFile(filepath.Join(path, "initial_results", "bad.json"), data, 0600))
			_, err = NewCorpus(path)
			require.ErrorContains(t, err, "bad.json")
		})
	}
}
