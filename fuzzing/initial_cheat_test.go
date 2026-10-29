package fuzzing

import (
	"context"
	"testing"

	"github.com/crytic/medusa-geth/common"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa/chain"
	chainConfig "github.com/crytic/medusa/chain/config"
	"github.com/crytic/medusa/fuzzing/config"
	"github.com/crytic/medusa/fuzzing/contracts"
	"github.com/stretchr/testify/require"
)

func TestInitialPropertyWithWarp(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_cheat.sol", solcVersion: "0.8.25",
		configUpdates: func(c *config.ProjectConfig) {
			initialTestConfig(c)
			c.Fuzzing.Workers = 1
			c.Fuzzing.Testing.PropertyTesting.CheckInitialState = true
		},
		method: func(fc *fuzzerTestContext) {
			require.NoError(fc.t, fc.fuzzer.Start())
			require.Len(fc.t, fc.fuzzer.TestCasesWithStatus(TestCaseStatusFailed), 1)
		},
	})
}

func TestInitialPropertyIsolation(t *testing.T) {
	runFuzzerTest(t, &fuzzerSolcFileTest{
		filePath: "testdata/contracts/properties/initial_cheat.sol", solcVersion: "0.8.25",
		configUpdates: initialTestConfig,
		method: func(fc *fuzzerTestContext) {
			var contract *contracts.Contract
			for _, candidate := range fc.fuzzer.contractDefinitions {
				if candidate.Name() == "TestContract" {
					contract = candidate
				}
			}
			require.NotNil(fc.t, contract)
			address := common.HexToAddress("0x123456")
			cfg, err := chainConfig.DefaultTestChainConfig()
			require.NoError(fc.t, err)
			cfg.CheatCodeConfig.EnableFFI = true
			ch, err := chain.NewTestChain(context.Background(), gethTypes.GenesisAlloc{address: {Code: contract.CompiledContract().RuntimeBytecode}}, cfg)
			require.NoError(fc.t, err)
			defer ch.Close()
			provider := &PropertyTestCaseProvider{fuzzer: fc.fuzzer}
			worker := &FuzzerWorker{fuzzer: fc.fuzzer, chain: ch}
			beforeHeader := gethTypes.CopyHeader(ch.Head().Header)
			beforeID := ch.ChainID()
			for _, traced := range []bool{true, false} {
				method := contracts.DeployedContractMethod{Address: address, Contract: contract, Method: contract.CompiledContract().Abi.Methods["checkIsolation"]}
				failed, trace, err := provider.checkPropertyTestFailed(worker, &method, traced)
				require.NoError(fc.t, err)
				if failed && trace != nil {
					fc.t.Log(trace.Log().String())
				}
				require.False(fc.t, failed)
				require.Nil(fc.t, ch.PendingBlock())
				require.Equal(fc.t, beforeHeader, ch.Head().Header)
				require.Equal(fc.t, beforeID, ch.ChainID())
				require.NotContains(fc.t, ch.Labels, address)
				require.Equal(fc.t, common.Hash{}, ch.State().GetState(address, common.Hash{}))
				method.Method = contract.CompiledContract().Abi.Methods["checkCaughtRevert"]
				_, _, err = provider.checkPropertyTestFailed(worker, &method, traced)
				require.ErrorContains(fc.t, err, "revertTo")
				require.Nil(fc.t, ch.PendingBlock())
				require.Equal(fc.t, beforeHeader, ch.Head().Header)
				method.Method = contract.CompiledContract().Abi.Methods["checkCaughtFFI"]
				_, _, err = provider.checkPropertyTestFailed(worker, &method, traced)
				require.ErrorContains(fc.t, err, "ffi")
				require.Nil(fc.t, ch.PendingBlock())
				require.Equal(fc.t, beforeHeader, ch.Head().Header)
				require.Equal(fc.t, beforeID, ch.ChainID())
				require.NotContains(fc.t, ch.Labels, address)
				require.Equal(fc.t, common.Hash{}, ch.State().GetState(address, common.Hash{}))
			}
		},
	})
}
