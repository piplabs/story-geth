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

package legacypool

import (
	"crypto/ecdsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/event"
	"github.com/ethereum/go-ethereum/params"
)

// TestSlowSenderRejectsAndEvicts pins the pool-level half of the watchdog defense:
// once a sender is denylisted, its transactions already in the pool are evicted and
// fresh ones rejected at ingress, freeing slots for legitimate transactions. Keyed
// on the signer, a different sender to the same recipient is unaffected - so the
// shared recipient contract is never censored.
func TestSlowSenderRejectsAndEvicts(t *testing.T) {
	t.Parallel()

	statedb, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	const blockGas = uint64(10_000_000)
	blockchain := newTestBlockChain(params.TestChainConfig, blockGas, statedb, new(event.Feed))

	pool := New(testTxPoolConfig, blockchain)
	if err := pool.Init(testTxPoolConfig.PriceLimit, blockchain.CurrentBlock(), newReserver()); err != nil {
		t.Fatal(err)
	}
	<-pool.initDoneCh
	defer pool.Close()

	attacker, _ := crypto.GenerateKey()
	innocent, _ := crypto.GenerateKey()
	attackerAddr := crypto.PubkeyToAddress(attacker.PublicKey)
	for _, k := range []*ecdsa.PrivateKey{attacker, innocent} {
		testAddBalance(pool, crypto.PubkeyToAddress(k.PublicKey), new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(1000)))
	}
	// Both senders call the same shared recipient.
	shared := common.HexToAddress("0x000000000000000000000000000000000000c0de")
	mkTx := func(nonce uint64, key *ecdsa.PrivateKey) *types.Transaction {
		tx, _ := types.SignTx(types.NewTransaction(nonce, shared, big.NewInt(0), 100000, big.NewInt(1), nil), types.HomesteadSigner{}, key)
		return tx
	}

	// Before denylisting, the attacker's tx is admitted and sits in the pool.
	atk := mkTx(0, attacker)
	if err := pool.Add([]*types.Transaction{atk}, true)[0]; err != nil {
		t.Fatalf("pre-denylist tx should be admitted, got %v", err)
	}
	if pool.Get(atk.Hash()) == nil {
		t.Fatal("pre-denylist tx should be in the pool")
	}

	// Denylisting the sender evicts its pooled tx via the evict hook.
	pool.SlowSenders().Add(attackerAddr)
	if pool.Get(atk.Hash()) != nil {
		t.Fatal("denylisting the sender must evict its pooled tx")
	}

	// A fresh tx from the same sender is rejected at ingress.
	atk2 := mkTx(1, attacker)
	if err := pool.Add([]*types.Transaction{atk2}, true)[0]; !errors.Is(err, txpool.ErrSlowSender) {
		t.Fatalf("denylisted sender: want ErrSlowSender, got %v", err)
	}
	if pool.Get(atk2.Hash()) != nil {
		t.Fatal("rejected tx must not be in the pool")
	}

	// A different sender to the SAME recipient is unaffected - the shared contract
	// is not censored.
	good := mkTx(0, innocent)
	if err := pool.Add([]*types.Transaction{good}, true)[0]; err != nil {
		t.Fatalf("innocent sender to the same recipient should be admitted, got %v", err)
	}
	if pool.Get(good.Hash()) == nil {
		t.Fatal("innocent sender's tx should be in the pool")
	}
}
