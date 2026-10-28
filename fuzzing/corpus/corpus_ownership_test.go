package corpus

import (
	"testing"

	"github.com/crytic/medusa/fuzzing/calls"
	"github.com/crytic/medusa/utils/randomutils"
	"github.com/stretchr/testify/require"
)

func TestCorpusOwnsMutationSequence(t *testing.T) {
	c, err := NewCorpus("")
	require.NoError(t, err)
	c.mutationTargetSequenceChooser = randomutils.NewWeightedRandomChooser[calls.CallSequence]()
	sequence := getMockCallSequence(1)
	nonce := sequence[0].Call.Nonce
	require.NoError(t, c.MarkCallSequenceForMutation(sequence, nil))
	sequence[0].Call.Nonce++
	copy, err := c.RandomMutationTargetSequence()
	require.NoError(t, err)
	require.Equal(t, nonce, copy[0].Call.Nonce, "corpus must not retain the worker's mutable message")
}

func TestCorpusOwnsStoredSequence(t *testing.T) {
	c, err := NewCorpus("")
	require.NoError(t, err)
	sequence := getMockCallSequence(1)
	nonce := sequence[0].Call.Nonce
	require.NoError(t, c.AddTestResultCallSequence(sequence, nil, false))
	sequence[0].Call.Nonce++
	require.Equal(t, nonce, c.testResultSequenceFiles.files[0].data[0].Call.Nonce)
}
