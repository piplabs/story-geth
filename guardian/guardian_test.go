package guardian

import (
	"math/big"
	"os"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/cipherowl-ai/openECS/address"
	"github.com/cipherowl-ai/openECS/store"
)

var (
	initMutex sync.Mutex
)

func TestGetInstance(t *testing.T) {
	type args struct {
		config Config
	}
	tests := []struct {
		name    string
		args    *args
		prepare func(a *args)
		want    bool
	}{
		{
			name: "instance not initialized",
			args: new(args),
			prepare: func(a *args) {
				a.config.Enabled = false
			},
			want: false,
		},
		{
			name: "instance initialized",
			args: new(args),
			prepare: func(a *args) {
				a.config.Enabled = true
			},
			want: true,
		},
	}
	for _, tt := range tests {
		if tt.prepare != nil {
			tt.prepare(tt.args)
		}

		t.Run(tt.name, func(t *testing.T) {
			testInitInstance(t, tt.args.config.Enabled, "")
			defer reset()
			g := GetInstance()
			if (g != nil) != tt.want {
				t.Errorf("GetInstance() instance = %v, want %v", g, tt.want)
				return
			}
		})
	}
}

func TestGuardian_CheckTransaction(t *testing.T) {
	type args struct {
		signer          types.Signer
		tx              *types.Transaction
		testFromAddress string
	}
	tests := []struct {
		name    string
		args    *args
		prepare func(a *args)
		want    bool
	}{
		{
			name: "not filtered",
			args: new(args),
			prepare: func(a *args) {
				key, _ := crypto.GenerateKey()
				signer := types.NewEIP155Signer(big.NewInt(18))

				tx, err := types.SignTx(types.NewTransaction(0, common.HexToAddress("0x810205E412eB4b9f8A7faEF8faE4cF08D7c680e1"), new(big.Int), 0, new(big.Int), nil), signer, key)
				if err != nil {
					t.Fatal(err)
				}

				a.signer = signer
				a.tx = tx
			},
			want: false,
		}, {
			name: "should filter 'to' address",
			args: new(args),
			prepare: func(a *args) {
				key, _ := crypto.GenerateKey()
				signer := types.NewEIP155Signer(big.NewInt(18))

				tx, err := types.SignTx(types.NewTransaction(0, common.HexToAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"), new(big.Int), 0, new(big.Int), nil), signer, key)
				if err != nil {
					t.Fatal(err)
				}

				a.signer = signer
				a.tx = tx
			},
			want: true,
		},
		{
			name: "should filter 'from' address",
			args: new(args),
			prepare: func(a *args) {
				key, _ := crypto.GenerateKey()
				signer := types.NewEIP155Signer(big.NewInt(18))

				tx, err := types.SignTx(types.NewTransaction(0, common.HexToAddress("0x810205E412eB4b9f8A7faEF8faE4cF08D7c680e1"), new(big.Int), 0, new(big.Int), nil), signer, key)
				if err != nil {
					t.Fatal(err)
				}

				a.signer = signer
				a.tx = tx

				from, err := types.Sender(signer, tx)
				if err != nil {
					t.Fatal(err)
				}
				a.testFromAddress = from.Hex()
			},
			want: true,
		},
	}
	for _, tt := range tests {
		if tt.prepare != nil {
			tt.prepare(tt.args)
		}
		t.Run(tt.name, func(t *testing.T) {
			testInitInstance(t, true, tt.args.testFromAddress)
			g := GetInstance()
			defer reset()

			if got := g.CheckTransaction(tt.args.signer, tt.args.tx); got != tt.want {
				t.Errorf("CheckSanctionedTransaction() = %v, want %v", got, tt.want)
			}
		})
	}
}

func testInitInstance(t *testing.T, enabled bool, testFromAddress string) {
	bf, err := store.NewBloomFilterStore(&address.EVMAddressHandler{})
	if err != nil {
		t.Fatal(err)
	}

	_ = bf.AddAddress("0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266")
	_ = bf.AddAddress("0x97DCA899a2278d010d678d64fBC7C718eD5D4939")
	if testFromAddress != "" {
		_ = bf.AddAddress(testFromAddress)
	}

	filterFilePath := testSaveBloomFilterToFile(t, bf)
	defer os.Remove(filterFilePath)

	InitInstance(Config{
		Enabled:        enabled,
		FilterFilePath: filterFilePath,
	})
}

func testSaveBloomFilterToFile(t *testing.T, bf *store.BloomFilterStore) string {
	filePath := os.TempDir() + "/bloom_filter.gob"
	if err := bf.SaveToFile(filePath); err != nil {
		t.Fatalf("Failed to save Bloom filter to file: %v", err)
	}

	return filePath
}

// reset allows you to reset the Guardian instance.
// This stops the current instance and resets it to nil.
func reset() {
	// If an instance exists, safely stop it.
	if instance != nil {
		instance.Stop()
	}

	initMutex.Lock()
	defer initMutex.Unlock()
	// Clear the instance by setting it to nil
	instance = nil

	// Also reset the initialization "once" guard,
	// so it can be initialized again in the future.
	initOnce = sync.Once{}
}
