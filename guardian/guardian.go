package guardian

import (
	"context"
	"os/user"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"

	"github.com/cipherowl-ai/addressdb/address"
	"github.com/cipherowl-ai/addressdb/reload"
	"github.com/cipherowl-ai/addressdb/store"
)

const (
	bloomFilterFilename = "bloom_filter.gob"

	linuxPath  = ".story/geth/guardian"
	darwinPath = "Library/Story/geth/guardian"
)

var (
	instance  *Guardian
	initOnce  sync.Once
	basicPath = getDefaultPath()
)

// Guardian provides transaction filtering to prevent interactions with certain pre-defined addresses.
type Guardian struct {
	filter  *store.BloomFilterStore // Stores addresses that are filtered
	manager *reload.ReloadManager   // Manages reloading of the filter data
	mu      sync.Mutex              // Mutex to control access to the Guardian's operations
}

// Config represents the configuration for initializing Guardian.
type Config struct {
	Enabled        bool   // If true, the Guardian will filter transactions
	FilterFilePath string // File path to the bloom filter file
}

// DefaultConfig contains the default configuration for Guardian.
var DefaultConfig = Config{
	FilterFilePath: filepath.Join(basicPath, bloomFilterFilename),
}

// InitInstance initializes a singleton instance of the Guardian with the given configuration.
// If the configuration disables the Guardian, the instance is not created.
func InitInstance(config Config) {
	initOnce.Do(func() {
		if !config.Enabled {
			log.Info("Guardian is disabled")
			return
		}

		var err error
		instance, err = newGuardian(config)
		if err != nil {
			log.Error("Failed to initialize Guardian", "error", err)
			return
		}
		log.Info("Guardian initialized", "file", config.FilterFilePath)
	})
}

// GetInstance returns the singleton Guardian instance.
func GetInstance() *Guardian {
	return instance
}

// newGuardian creates a new Guardian instance from the provided config.
func newGuardian(config Config) (*Guardian, error) {
	// Create the bloom filter from file
	filter, err := store.NewBloomFilterStoreFromFile(config.FilterFilePath, &address.EVMAddressHandler{})
	if err != nil {
		return nil, err
	}

	// Create file notifier for dynamic filter reload
	notifier, err := reload.NewFileWatcherNotifier(config.FilterFilePath, 10*time.Second)
	if err != nil {
		return nil, err
	}

	// Start reload manager
	manager := reload.NewReloadManager(filter, notifier)
	if err := manager.Start(context.Background()); err != nil {
		return nil, err
	}

	return &Guardian{
		filter:  filter,
		manager: manager,
	}, nil
}

// CheckTransaction checks if the sender or recipient in the transaction is in the filter file.
// Returns true if the transaction interacts with any filtered addresses.
func (p *Guardian) CheckTransaction(signer types.Signer, tx *types.Transaction) bool {
	// Extract the sender's address
	from, err := types.Sender(signer, tx)
	if err != nil {
		log.Error("Failed to extract 'from' address", "err", err)
		return false
	}

	// Check the sender's address
	if filtered, err := p.checkAddress(tx, from.Hex(), from.Hex()); err != nil || filtered {
		if err != nil {
			log.Error("Error checking sender address", "err", err)
		}
		return filtered
	}

	// Check the recipient's address if applicable
	if to := tx.To(); to != nil {
		if filtered, err := p.checkAddress(tx, from.Hex(), to.Hex()); err != nil || filtered {
			if err != nil {
				log.Error("Error checking recipient address", "err", err)
			}
			return filtered
		}
	}

	return false
}

// Stop shuts down Guardian, stops the filter reload manager safely.
func (p *Guardian) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.manager != nil {
		_ = p.manager.Stop()
	}
}

// checkAddress checks if the given address is in the filter list.
func (p *Guardian) checkAddress(tx *types.Transaction, from, addr string) (bool, error) {
	ok, err := p.filter.CheckAddress(addr)
	if err != nil {
		return false, err
	}
	if ok {
		logFilteredEntry(filteredTxLog{filteredAddress: addr, from: from, transaction: tx})
		log.Warn("Filtered address found in transaction", "tx", tx.Hash().Hex(), "address", addr)
		return true, nil
	}

	return false, nil
}

// getDefaultPath determines the default file path based on the operating system.
func getDefaultPath() string {
	u, err := user.Current()
	if err != nil {
		log.Error("Failed to get current user", "err", err)
		return ""
	}

	switch runtime.GOOS {
	case "linux":
		return filepath.Join(u.HomeDir, linuxPath)
	case "darwin":
		return filepath.Join(u.HomeDir, darwinPath)
	default:
		log.Error("Unsupported OS for guardian", "os", runtime.GOOS)
		return ""
	}
}
