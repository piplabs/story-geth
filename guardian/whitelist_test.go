package guardian

import (
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestGetWhitelistInstance(t *testing.T) {
	type args struct {
		config WhiteListConfig
	}
	tests := []struct {
		name    string
		args    *args
		prepare func(a *args)
		want    bool
	}{
		{
			name: "whitelist instance not initialized",
			args: new(args),
			prepare: func(a *args) {
				a.config.Enabled = false
			},
			want: false,
		},
		{
			name: "whitelist instance initialized",
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
			testInitWhitelistInstance(t, tt.args.config.Enabled, "")
			defer reset()
			w := GetWhitelistInstance()
			if (w != nil) != tt.want {
				t.Errorf("GetInstance() instance = %v, want %v", w, tt.want)
				return
			}
		})
	}
}

func TestIsWhitelisted(t *testing.T) {
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
			name: "whitelisted",
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
		{
			name: "not whitelisted",
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
		},
	}
	for _, tt := range tests {
		if tt.prepare != nil {
			tt.prepare(tt.args)
		}

		t.Run(tt.name, func(t *testing.T) {
			testInitWhitelistInstance(t, true, tt.args.testFromAddress)
			defer reset()
			w := GetWhitelistInstance()
			if got := w.IsWhitelisted(tt.args.signer, tt.args.tx); got != tt.want {
				t.Errorf("IsWhitelisted() = %v, want %v", got, tt.want)
			}
		})
	}
}

func testInitWhitelistInstance(t *testing.T, enabled bool, testFromAddress string) {
	filePath := filepath.Join(os.TempDir(), "whitelistedAddresses.json")
	defer os.Remove(filePath)

	whitelistAddresses := struct {
		WhitelistedAddresses []string `json:"whitelistedAddresses"`
	}{
		WhitelistedAddresses: []string{
			"0x1234567890abcdef1234567890abcdef12345678",
			"0xabcdef1234567890abcdef1234567890abcdef12",
		},
	}
	if testFromAddress != "" {
		whitelistAddresses.WhitelistedAddresses = append(whitelistAddresses.WhitelistedAddresses, testFromAddress)
	}
	whitelistData, err := json.Marshal(whitelistAddresses)
	if err != nil {
		t.Fatalf("failed to marshal whitelist addresses: %v", err)
	}
	if err := os.WriteFile(filePath, whitelistData, 0644); err != nil {
		t.Fatalf("failed to write whitelist file: %v", err)
	}

	InitWhiteList(WhiteListConfig{
		Enabled:  enabled,
		FilePath: filePath,
	})
}
