// Copyright 2025 The go-ethereum Authors
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

package miner

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// TestMinerTxExecTimeoutEjectsSlowTx pins the watchdog behaviour: a single
// transaction whose execution would run far past the per-tx budget is ejected
// from the block, the builder continues with the remaining transactions, and
// the ejected transaction's gas is not accounted to the block.
func TestMinerTxExecTimeoutEjectsSlowTx(t *testing.T) {
	// Infinite loop: JUMPDEST PUSH1 0x00 JUMP. With a block-sized gas limit this
	// runs for many seconds before OOG, so a non-firing watchdog hangs the build.
	loopCode := []byte{0x5b, 0x60, 0x00, 0x56}
	loopAddr := common.HexToAddress("0x000000000000000000000000000000000000c0de")

	attackerKey, _ := crypto.GenerateKey()
	attackerAddr := crypto.PubkeyToAddress(attackerKey.PublicKey)

	chainConfig := new(params.ChainConfig)
	*chainConfig = *params.TestChainConfig

	const blockGas = uint64(5_000_000_000)
	hugeFunds := new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(1_000_000))

	gspec := &core.Genesis{
		Config:   chainConfig,
		GasLimit: blockGas,
		Alloc: types.GenesisAlloc{
			testBankAddress: {Balance: hugeFunds},
			attackerAddr:    {Balance: hugeFunds},
			loopAddr:        {Code: loopCode, Balance: common.Big0},
		},
	}

	db := rawdb.NewMemoryDatabase()
	engine := ethash.NewFaker()
	chain, err := core.NewBlockChain(db, gspec, engine, &core.BlockChainConfig{ArchiveMode: true})
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}
	defer chain.Stop()

	pool := legacypool.New(testTxPoolConfig, chain)
	pl, err := txpool.New(testTxPoolConfig.PriceLimit, chain, []txpool.SubPool{pool})
	if err != nil {
		t.Fatalf("create txpool: %v", err)
	}
	defer pl.Close()
	backend := &testWorkerBackend{db: db, chain: chain, txPool: pl, genesis: gspec}

	cfg := Config{
		PendingFeeRecipient: testBankAddress,
		Recommit:            2 * time.Second,
		GasCeil:             blockGas,
		GasPrice:            big.NewInt(0),
		TxExecTimeout:       100 * time.Millisecond,
	}
	w := New(backend, cfg, engine)

	signer := types.LatestSigner(chainConfig)
	// Higher tip so the spinner is selected first: this proves the builder is not
	// stalled by the highest-priority transaction and still packs the rest.
	spinner := types.MustSignNewTx(attackerKey, signer, &types.LegacyTx{
		Nonce:    0,
		To:       &loopAddr,
		Gas:      blockGas,
		GasPrice: big.NewInt(3 * params.InitialBaseFee),
	})
	transfer := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{
		Nonce:    0,
		To:       &testUserAddress,
		Value:    big.NewInt(1000),
		Gas:      params.TxGas,
		GasPrice: big.NewInt(2 * params.InitialBaseFee),
	})
	for _, e := range backend.txPool.Add([]*types.Transaction{spinner, transfer}, true) {
		if e != nil {
			t.Fatalf("txpool add: %v", e)
		}
	}

	genParams := &generateParams{
		timestamp: uint64(time.Now().Unix()),
		forceTime: true,
		coinbase:  testBankAddress,
		noTxs:     false,
	}

	type result struct {
		r       *newPayloadResult
		elapsed time.Duration
	}
	done := make(chan result, 1)
	go func() {
		start := time.Now()
		r := w.generateWork(genParams, false)
		done <- result{r, time.Since(start)}
	}()

	select {
	case got := <-done:
		if got.r.err != nil {
			t.Fatalf("generateWork: %v", got.r.err)
		}
		if got.elapsed > 5*time.Second {
			t.Fatalf("build took %v: watchdog did not bound the spinner", got.elapsed)
		}
		txs := got.r.block.Transactions()
		if len(txs) != 1 {
			t.Fatalf("want 1 tx in block, got %d", len(txs))
		}
		if txs[0].Hash() != transfer.Hash() {
			t.Fatalf("included tx = %s, want transfer %s (spinner should be ejected)", txs[0].Hash(), transfer.Hash())
		}
		if got.r.block.GasUsed() != params.TxGas {
			t.Fatalf("block GasUsed = %d, want %d (ejected spinner gas must be reverted)", got.r.block.GasUsed(), params.TxGas)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("generateWork stuck on spinner — watchdog never fired")
	}
}
