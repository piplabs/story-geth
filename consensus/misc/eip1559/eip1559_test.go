// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package eip1559

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// copyConfig does a _shallow_ copy of a given config. Safe to set new values, but
// do not use e.g. SetInt() on the numbers. For testing only
func copyConfig(original *params.ChainConfig) *params.ChainConfig {
	return &params.ChainConfig{
		ChainID:                 original.ChainID,
		HomesteadBlock:          original.HomesteadBlock,
		DAOForkBlock:            original.DAOForkBlock,
		DAOForkSupport:          original.DAOForkSupport,
		EIP150Block:             original.EIP150Block,
		EIP155Block:             original.EIP155Block,
		EIP158Block:             original.EIP158Block,
		ByzantiumBlock:          original.ByzantiumBlock,
		ConstantinopleBlock:     original.ConstantinopleBlock,
		PetersburgBlock:         original.PetersburgBlock,
		IstanbulBlock:           original.IstanbulBlock,
		MuirGlacierBlock:        original.MuirGlacierBlock,
		BerlinBlock:             original.BerlinBlock,
		LondonBlock:             original.LondonBlock,
		TerminalTotalDifficulty: original.TerminalTotalDifficulty,
		Ethash:                  original.Ethash,
		Clique:                  original.Clique,
	}
}

func config() *params.ChainConfig {
	config := copyConfig(params.TestChainConfig)
	config.LondonBlock = big.NewInt(5)
	return config
}

// TestBlockGasLimits tests the gasLimit checks for blocks both across
// the EIP-1559 boundary and post-1559 blocks
func TestBlockGasLimits(t *testing.T) {
	initial := new(big.Int).SetUint64(params.InitialBaseFee)

	for i, tc := range []struct {
		pGasLimit uint64
		pNum      int64
		gasLimit  uint64
		ok        bool
	}{
		// Transitions from non-london to london
		{10000000, 4, 20000000, true},  // No change
		{10000000, 4, 20019530, true},  // Upper limit
		{10000000, 4, 20019531, false}, // Upper +1
		{10000000, 4, 19980470, true},  // Lower limit
		{10000000, 4, 19980469, false}, // Lower limit -1
		// London to London
		{20000000, 5, 20000000, true},
		{20000000, 5, 20019530, true},  // Upper limit
		{20000000, 5, 20019531, false}, // Upper limit +1
		{20000000, 5, 19980470, true},  // Lower limit
		{20000000, 5, 19980469, false}, // Lower limit -1
		{40000000, 5, 40039061, true},  // Upper limit
		{40000000, 5, 40039062, false}, // Upper limit +1
		{40000000, 5, 39960939, true},  // lower limit
		{40000000, 5, 39960938, false}, // Lower limit -1
	} {
		parent := &types.Header{
			GasUsed:  tc.pGasLimit / 2,
			GasLimit: tc.pGasLimit,
			BaseFee:  initial,
			Number:   big.NewInt(tc.pNum),
		}
		header := &types.Header{
			GasUsed:  tc.gasLimit / 2,
			GasLimit: tc.gasLimit,
			BaseFee:  initial,
			Number:   big.NewInt(tc.pNum + 1),
		}
		err := VerifyEIP1559Header(config(), parent, header)
		if tc.ok && err != nil {
			t.Errorf("test %d: Expected valid header: %s", i, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("test %d: Expected invalid header", i)
		}
	}
}

// TestCalcBaseFee assumes all blocks are 1559-blocks
func TestCalcBaseFee(t *testing.T) {
	tests := []struct {
		parentBaseFee   int64
		parentGasLimit  uint64
		parentGasUsed   uint64
		expectedBaseFee int64
	}{
		{params.InitialBaseFee, 20000000, 10000000, params.InitialBaseFee}, // usage == target
		{params.InitialBaseFee, 20000000, 9000000, 987500000},              // usage below target
		{params.InitialBaseFee, 20000000, 11000000, 1012500000},            // usage above target
	}
	for i, test := range tests {
		parent := &types.Header{
			Number:   common.Big32,
			GasLimit: test.parentGasLimit,
			GasUsed:  test.parentGasUsed,
			BaseFee:  big.NewInt(test.parentBaseFee),
		}
		if have, want := CalcBaseFee(config(), parent), big.NewInt(test.expectedBaseFee); have.Cmp(want) != 0 {
			t.Errorf("test %d: have %d  want %d, ", i, have, want)
		}
	}
}

// storyConfig returns a Story-chain ChainConfig with Amsterdam optionally activated.
// Caller passes activateAmsterdam=true to enable the minBaseFee floor.
func storyConfig(activateAmsterdam bool) *params.ChainConfig {
	cfg := &params.ChainConfig{
		ChainID:                 big.NewInt(int64(params.IDStoryMainnet)),
		HomesteadBlock:          big.NewInt(0),
		EIP150Block:             big.NewInt(0),
		EIP155Block:             big.NewInt(0),
		EIP158Block:             big.NewInt(0),
		ByzantiumBlock:          big.NewInt(0),
		ConstantinopleBlock:     big.NewInt(0),
		PetersburgBlock:         big.NewInt(0),
		IstanbulBlock:           big.NewInt(0),
		BerlinBlock:             big.NewInt(0),
		LondonBlock:             big.NewInt(0),
		TerminalTotalDifficulty: big.NewInt(0),
		ShanghaiTime:            newUint64Ptr(0),
		CancunTime:              newUint64Ptr(0),
		PragueTime:              newUint64Ptr(0),
		OsakaTime:               newUint64Ptr(0),
	}
	if activateAmsterdam {
		cfg.AmsterdamTime = newUint64Ptr(0)
	}
	return cfg
}

func newUint64Ptr(v uint64) *uint64 { return &v }

// TestCalcBaseFeeMinBaseFeeFloor verifies the Amsterdam-gated minBaseFee floor.
func TestCalcBaseFeeMinBaseFeeFloor(t *testing.T) {
	floor := new(big.Int).SetUint64(params.DefaultMinBaseFeeStory) // 1 gwei
	belowFloor := big.NewInt(23)                                   // observed cold-state baseFee
	aboveFloor := new(big.Int).Mul(floor, big.NewInt(5))           // 5 gwei

	tests := []struct {
		name              string
		activateAmsterdam bool
		parentBaseFee     *big.Int
		parentGasLimit    uint64
		parentGasUsed     uint64
		parentTime        uint64
		expected          *big.Int
	}{
		{
			// Pre-Amsterdam: floor not enforced, baseFee decays freely toward 0.
			name:              "pre-fork floor not applied",
			activateAmsterdam: false,
			parentBaseFee:     belowFloor,
			parentGasLimit:    20000000,
			parentGasUsed:     0,
			parentTime:        0,
			expected:          big.NewInt(23), // unchanged (zero gas decay produces ~same value)
		},
		{
			// Post-Amsterdam, parent baseFee well below floor, low utilization:
			// natural calculation would stay below floor; clamp to floor.
			name:              "below floor + low util clamps up",
			activateAmsterdam: true,
			parentBaseFee:     belowFloor,
			parentGasLimit:    20000000,
			parentGasUsed:     0,
			parentTime:        1,
			expected:          floor,
		},
		{
			// Post-Amsterdam, parent baseFee already at floor, zero utilization:
			// would normally decay, but stays at floor.
			name:              "at floor + low util stays at floor",
			activateAmsterdam: true,
			parentBaseFee:     new(big.Int).Set(floor),
			parentGasLimit:    20000000,
			parentGasUsed:     0,
			parentTime:        1,
			expected:          floor,
		},
		{
			// Post-Amsterdam, baseFee above floor, high utilization:
			// floor does not cap upward movement.
			name:              "above floor + high util unaffected",
			activateAmsterdam: true,
			parentBaseFee:     aboveFloor,
			parentGasLimit:    20000000,
			parentGasUsed:     20000000, // 2x target -> baseFee rises
			parentTime:        1,
			expected: func() *big.Int {
				// parent 5 gwei + 5 gwei/8 = 5.625 gwei (denom default 8 in non-Story test cfg)
				// But storyConfig uses Story chain id; denom is 24 for non-Iliad/Aeneid.
				delta := new(big.Int).Set(aboveFloor)
				delta.Div(delta, big.NewInt(int64(params.DefaultBaseFeeChangeDenomStory)))
				return new(big.Int).Add(aboveFloor, delta)
			}(),
		},
		{
			// Post-Amsterdam, parent at floor, high utilization: floor allows rise above.
			name:              "at floor + high util rises above floor",
			activateAmsterdam: true,
			parentBaseFee:     new(big.Int).Set(floor),
			parentGasLimit:    20000000,
			parentGasUsed:     20000000,
			parentTime:        1,
			expected: func() *big.Int {
				delta := new(big.Int).Set(floor)
				delta.Div(delta, big.NewInt(int64(params.DefaultBaseFeeChangeDenomStory)))
				return new(big.Int).Add(floor, delta)
			}(),
		},
		{
			// Post-Amsterdam, parent above floor, zero utilization: decay capped at floor.
			name:              "above floor + zero util decays only to floor",
			activateAmsterdam: true,
			parentBaseFee:     new(big.Int).Mul(floor, big.NewInt(2)), // 2 gwei
			parentGasLimit:    20000000,
			parentGasUsed:     0,
			parentTime:        1,
			expected: func() *big.Int {
				// natural decay: 2 gwei - 2 gwei / 24 = 1.9167 gwei (still above floor)
				start := new(big.Int).Mul(floor, big.NewInt(2))
				delta := new(big.Int).Set(start)
				delta.Div(delta, big.NewInt(int64(params.DefaultBaseFeeChangeDenomStory)))
				return new(big.Int).Sub(start, delta)
			}(),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := storyConfig(tc.activateAmsterdam)
			parent := &types.Header{
				Number:   big.NewInt(100),
				Time:     tc.parentTime,
				GasLimit: tc.parentGasLimit,
				GasUsed:  tc.parentGasUsed,
				BaseFee:  tc.parentBaseFee,
			}
			got := CalcBaseFee(cfg, parent)
			if got.Cmp(tc.expected) != 0 {
				t.Errorf("baseFee mismatch: have %s, want %s", got, tc.expected)
			}
		})
	}
}

// TestCalcBaseFeeFloorOnlyOnStoryChain verifies non-Story chains never enforce the floor.
func TestCalcBaseFeeFloorOnlyOnStoryChain(t *testing.T) {
	// Use the default (non-Story) test config, set Amsterdam, parent baseFee below floor.
	cfg := copyConfig(params.TestChainConfig)
	cfg.LondonBlock = big.NewInt(0)
	cfg.AmsterdamTime = newUint64Ptr(0)

	parent := &types.Header{
		Number:   big.NewInt(100),
		Time:     1,
		GasLimit: 20000000,
		GasUsed:  0,
		BaseFee:  big.NewInt(23),
	}
	got := CalcBaseFee(cfg, parent)
	// On non-Story chain, baseFee can decay freely below the Story floor.
	// We just check that the result is NOT clamped to 1 gwei.
	if got.Cmp(new(big.Int).SetUint64(params.DefaultMinBaseFeeStory)) >= 0 {
		t.Errorf("expected baseFee below Story floor on non-Story chain, got %s", got)
	}
}
