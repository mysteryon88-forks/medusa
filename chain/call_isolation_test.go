package chain

import (
	"context"
	"math/big"
	"testing"

	"github.com/crytic/medusa-geth/common"
	"github.com/crytic/medusa-geth/core"
	gethTypes "github.com/crytic/medusa-geth/core/types"
	"github.com/crytic/medusa-geth/crypto"
	"github.com/stretchr/testify/require"
)

func isolatedTestMessage(to *common.Address, data []byte) *core.Message {
	return &core.Message{From: common.HexToAddress("0x1234"), To: to, GasLimit: 500000,
		Value: new(big.Int), GasPrice: big.NewInt(1), GasFeeCap: new(big.Int), GasTipCap: new(big.Int), Data: data}
}

func TestCallContractIsolatesOverrides(t *testing.T) {
	ch, err := NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer ch.Close()
	initCode := []byte{0x00}
	hash := crypto.Keccak256Hash(initCode)
	want := common.HexToAddress("0xabcd")
	ch.vmConfigExtensions.ContractAddressOverrides[hash] = want
	result, err := ch.CallContract(isolatedTestMessage(nil, initCode), nil)
	require.NoError(t, err)
	require.False(t, result.Failed())
	require.Equal(t, want, ch.vmConfigExtensions.ContractAddressOverrides[hash])
	require.Nil(t, ch.PendingBlock())
}

func TestCallContractUsesProvidedStateForCheatcodes(t *testing.T) {
	ch, err := NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer ch.Close()
	other, err := NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer other.Close()
	address := common.HexToAddress("0xabcdef")
	cheat := ch.CheatCodeContracts()[StandardCheatcodeContractAddress]
	method := cheat.Abi().Methods["deal(address,uint256)"]
	data, err := method.Inputs.Pack(address, big.NewInt(123))
	require.NoError(t, err)
	data = append(method.ID, data...)
	to := StandardCheatcodeContractAddress
	result, err := ch.CallContract(isolatedTestMessage(&to, data), other.State())
	require.NoError(t, err)
	require.False(t, result.Failed())
	require.Zero(t, ch.State().GetBalance(address).Sign())
	require.Zero(t, other.State().GetBalance(address).Sign())
	require.Nil(t, ch.PendingBlock())
}

func TestCallContractPreservesPendingBlockCheatcodeBehavior(t *testing.T) {
	ch, err := NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
	require.NoError(t, err)
	defer ch.Close()
	_, err = ch.PendingBlockCreate()
	require.NoError(t, err)
	cheat := ch.CheatCodeContracts()[StandardCheatcodeContractAddress]
	method := cheat.Abi().Methods["warp(uint256)"]
	data, err := method.Inputs.Pack(big.NewInt(12345))
	require.NoError(t, err)
	to := StandardCheatcodeContractAddress
	result, err := ch.CallContract(isolatedTestMessage(&to, append(method.ID, data...)), nil)
	require.NoError(t, err)
	require.False(t, result.Failed())
	require.EqualValues(t, 12345, ch.PendingBlock().Header.Time)
}

func TestCallContractSnapshotCheatcode(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "committed", true: "pending"}[pending], func(t *testing.T) {
			ch, err := NewTestChain(context.Background(), gethTypes.GenesisAlloc{}, nil)
			require.NoError(t, err)
			defer ch.Close()
			if pending {
				_, err = ch.PendingBlockCreate()
				require.NoError(t, err)
			}
			cheat := ch.CheatCodeContracts()[StandardCheatcodeContractAddress]
			method := cheat.Abi().Methods["snapshot()"]
			to := StandardCheatcodeContractAddress
			result, err := ch.CallContract(isolatedTestMessage(&to, method.ID), nil)
			require.NoError(t, err)
			require.False(t, result.Failed())
			values, err := method.Outputs.Unpack(result.Return())
			require.NoError(t, err)
			require.Len(t, values, 1)
			_, ok := values[0].(*big.Int)
			require.True(t, ok)
		})
	}
}
