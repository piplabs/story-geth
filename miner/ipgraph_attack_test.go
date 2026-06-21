// Copyright 2025 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// Faithful reproduction of the mainnet ipgraph getRoyalty gas-mispricing DoS:
// a contract loops the ipgraph precompile getRoyalty over a deep ancestor graph
// (priced as a fixed constant but doing a full topological traversal). Asserts the
// miner's per-tx watchdog ejects it while a normal transfer is still included.

package miner

import (
	"math/big"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/beacon"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/txpool"
	"github.com/ethereum/go-ethereum/core/txpool/legacypool"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
)

// runtime of: contract Loop { function attack(address,address,uint256) loops IP(0x101).getRoyalty }
const loopRuntimeHex = "0x608060405234801561000f575f5ffd5b5060043610610029575f3560e01c8063a237de6c1461002d575b5f5ffd5b61004061003b366004610119565b610042565b005b5f5b818110156100f8576040516001600160a01b038581166024830152841660448201525f60648201819052906101019060840160408051601f198184030181529181526020820180516001600160e01b031663a987a48160e01b179052516100ab9190610152565b5f60405180830381855afa9150503d805f81146100e3576040519150601f19603f3d011682016040523d82523d5f602084013e6100e8565b606091505b5050600190920191506100449050565b50505050565b80356001600160a01b0381168114610114575f5ffd5b919050565b5f5f5f6060848603121561012b575f5ffd5b610134846100fe565b9250610142602085016100fe565b9150604084013590509250925092565b5f82518060208501845e5f92019182525091905056fea2646970667358221220ce206cbcf8eae887bf18587f2e8af908cfc0eaaf0135cdeeeef4d4eb0d08ba3a64736f6c634300081d0033"

func TestMinerWatchdogEjectsIpgraphGetRoyaltyLoop(t *testing.T) {
	loopAddr := common.HexToAddress("0x000000000000000000000000000000000000c0de")
	ipgraph := common.HexToAddress("0x0000000000000000000000000000000000000101")
	acl := common.HexToAddress("0x1640A22a8A086747cD377b73954545e2Dfcc9Cad")
	aclSlot, _ := new(big.Int).SetString("af99b37fdaacca72ee7240cb1435cc9e498aee6ef4edc19c8cc0cd787f4e6800", 16)

	ipAddr := func(k int) common.Address { return common.BigToAddress(big.NewInt(int64(0x1000000 + k))) }
	const depth = 2000

	// Deep ancestor chain in ipgraph precompile storage: ipAddr(k) -> parent ipAddr(k+1).
	ipgStore := map[common.Hash]common.Hash{}
	for k := 1; k < depth; k++ {
		ipgStore[common.BytesToHash(ipAddr(k).Bytes())] = common.BigToHash(big.NewInt(1))
		slot := new(big.Int).SetBytes(crypto.Keccak256(ipAddr(k).Bytes()))
		ipgStore[common.BigToHash(slot)] = common.BytesToHash(ipAddr(k + 1).Bytes())
	}
	// ACL whitelist for the loop contract (getRoyalty checks the caller).
	aclStore := map[common.Hash]common.Hash{}
	pre := append(loopAddr.Bytes(), aclSlot.Bytes()...)
	aclStore[common.BytesToHash(crypto.Keccak256(pre))] = common.BigToHash(big.NewInt(1))

	attackerKey, _ := crypto.GenerateKey()
	attackerAddr := crypto.PubkeyToAddress(attackerKey.PublicKey)

	chainConfig := *params.MergedTestChainConfig
	const blockGas = uint64(100_000_000)
	hugeFunds := new(big.Int).Mul(big.NewInt(params.Ether), big.NewInt(1_000_000))

	gspec := &core.Genesis{
		Config:   &chainConfig,
		GasLimit: blockGas,
		Alloc: types.GenesisAlloc{
			testBankAddress: {Balance: hugeFunds},
			attackerAddr:    {Balance: hugeFunds},
			loopAddr:        {Code: common.FromHex(loopRuntimeHex), Balance: common.Big0},
			ipgraph:         {Balance: common.Big0, Storage: ipgStore},
			acl:             {Balance: common.Big0, Storage: aclStore},
		},
	}

	db := rawdb.NewMemoryDatabase()
	engine := beacon.New(ethash.NewFaker())
	chain, err := core.NewBlockChain(db, gspec, engine, &core.BlockChainConfig{ArchiveMode: true})
	if err != nil {
		t.Fatalf("create chain: %v", err)
	}
	defer chain.Stop()
	pool := legacypool.New(testTxPoolConfig, chain)
	pl, err := txpool.New(testTxPoolConfig.PriceLimit, chain, []txpool.SubPool{pool})
	if err != nil {
		t.Fatalf("txpool: %v", err)
	}
	defer pl.Close()
	backend := &testWorkerBackend{db: db, chain: chain, txPool: pl, genesis: gspec}

	cfg := Config{PendingFeeRecipient: testBankAddress, Recommit: 2 * time.Second, GasCeil: blockGas, GasPrice: big.NewInt(0), TxExecTimeout: 50 * time.Millisecond}
	w := New(backend, cfg, engine)
	signer := types.LatestSigner(&chainConfig)

	// staller: attacker calls loop.attack(leaf, root, hugeCount) -> loops getRoyalty
	pad := func(a common.Address) []byte { return common.LeftPadBytes(a.Bytes(), 32) }
	data := append([]byte{0xa2, 0x37, 0xde, 0x6c}, pad(ipAddr(1))...)
	data = append(data, pad(ipAddr(depth))...)
	data = append(data, common.LeftPadBytes(big.NewInt(1_000_000).Bytes(), 32)...)
	staller := types.MustSignNewTx(attackerKey, signer, &types.LegacyTx{Nonce: 0, To: &loopAddr, Gas: 16_777_216, GasPrice: big.NewInt(2 * params.InitialBaseFee), Data: data})
	transfer := types.MustSignNewTx(testBankKey, signer, &types.LegacyTx{Nonce: 0, To: &testUserAddress, Value: big.NewInt(1000), Gas: params.TxGas, GasPrice: big.NewInt(params.InitialBaseFee)})
	for _, e := range backend.txPool.Add([]*types.Transaction{staller, transfer}, true) {
		if e != nil {
			t.Fatalf("txpool add: %v", e)
		}
	}

	genParams := &generateParams{timestamp: uint64(time.Now().Unix()), forceTime: true, coinbase: testBankAddress, random: common.HexToHash("0x01"), noTxs: false}
	type res struct {
		r       *newPayloadResult
		elapsed time.Duration
	}
	done := make(chan res, 1)
	go func() { s := time.Now(); r := w.generateWork(genParams, false); done <- res{r, time.Since(s)} }()

	select {
	case got := <-done:
		if got.r.err != nil {
			t.Fatalf("generateWork: %v", got.r.err)
		}
		if got.elapsed > 5*time.Second {
			t.Fatalf("build took %v: watchdog did not bound the getRoyalty loop", got.elapsed)
		}
		txs := got.r.block.Transactions()
		if len(txs) != 1 || txs[0].Hash() != transfer.Hash() {
			t.Fatalf("want only the transfer included, got %d txs (getRoyalty-loop staller should be ejected)", len(txs))
		}
		t.Logf("ejected getRoyalty-loop staller %s after %v; block kept the normal transfer", staller.Hash().Hex(), got.elapsed)
		if got.r.block.GasUsed() != params.TxGas {
			t.Fatalf("block GasUsed = %d, want %d", got.r.block.GasUsed(), params.TxGas)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("generateWork stuck on getRoyalty loop — watchdog never fired")
	}
}
