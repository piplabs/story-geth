package guardian

import (
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const (
	whitelistFileName = "whitelistedAddresses.json"

	whitelistFileLinuxPath  = ".story/geth"
	whiteListFileDarwinPath = "Library/Story/geth"
)

var (
	whiteListInstance      *WhiteList
	whitelistFileBasicPath = getDefaultWhiteListFilePath()
)

// Whitelist should only be used in singularity stage.
// Only addresses in the whitelist are allowed to send transactions.
type WhiteList struct {
	Addresses map[string]struct{}
}

type WhiteListConfig struct {
	Enabled  bool
	FilePath string
}

var DefaultWhiteListConfig = WhiteListConfig{
	FilePath: filepath.Join(whitelistFileBasicPath, whitelistFileName),
}

func InitWhiteList(config WhiteListConfig) error {
	if !config.Enabled {
		log.Info("Whitelist module is disabled")
		return nil
	}
	data, err := os.ReadFile(config.FilePath)
	if err != nil {
		log.Error("Failed to read whitelist file", "err", err)
		return err
	}
	if len(data) == 0 {
		return errors.New("whitelist file should not be empty when whitelist module is enabled")
	}
	var c struct {
		WhitelistedAddresses []string `json:"whitelistedAddresses"`
	}
	if err := json.Unmarshal(data, &c); err != nil {
		log.Error("Failed to unmarshal whitelist file", "err", err)
		return err
	}

	whiteListedAddresses := make(map[string]struct{}, len(c.WhitelistedAddresses))
	for _, addr := range c.WhitelistedAddresses {
		whiteListedAddresses[strings.ToLower(addr)] = struct{}{}
	}
	whiteListInstance = &WhiteList{
		Addresses: whiteListedAddresses,
	}
	log.Info("Whitelist module enabled and initialized")
	return nil
}

func GetWhitelistInstance() *WhiteList {
	return whiteListInstance
}

func (w *WhiteList) IsWhitelisted(signer types.Signer, tx *types.Transaction) bool {
	from, err := types.Sender(signer, tx)
	if err != nil {
		log.Error("Failed to extract 'from' address", "err", err)
		return false
	}
	_, ok := w.Addresses[strings.ToLower(from.Hex())]
	return ok
}

func getDefaultWhiteListFilePath() string {
	u, err := user.Current()
	if err != nil {
		log.Error("Failed to get current user", "err", err)
		return ""
	}

	switch runtime.GOOS {
	case "linux":
		return filepath.Join(u.HomeDir, whitelistFileLinuxPath)
	case "darwin":
		return filepath.Join(u.HomeDir, whiteListFileDarwinPath)
	default:
		log.Error("Unsupported OS for guardian", "os", runtime.GOOS)
		return ""
	}
}
