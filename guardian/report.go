package guardian

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// filteredReportFileName represents the log filename for storing filtered transactions.
	filteredReportFileName = "filtered_report.log"
)

var (
	// filteredCache is a concurrent map to store filtered addresses.
	filteredCache = sync.Map{}

	// txLogChan is a channel for sending filtered transaction logs.
	txLogChan chan filteredTxLog
)

// InitFilteredReport initializes the filtered report functionality based on the provided configuration.
func InitFilteredReport(config Config) {
	if !config.Enabled {
		log.Info("Guardian is disabled, filtered report will not be generated.")
		return
	}
	txLogChan = make(chan filteredTxLog, 100)

	// Start a goroutine to handle logging of filtered transactions.
	// Avoid triggering I/O performance issues and potential file lock
	// contention under high concurrency conditions.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Error("Recovered from panic in logFilteredEntry goroutine", "error", r)
			}
		}()

		for txLog := range txLogChan {
			// Append the log entry to the file
			if err := appendToFile(txLog); err != nil {
				log.Error("Failed to log filtered transaction", "err", err)
			}
		}
	}()
}

// filteredTxLog represents the details of a filtered transaction entry.
type filteredTxLog struct {
	filteredAddress string             // Target address that triggered the filter
	from            string             // Sender address of the transaction
	transaction     *types.Transaction // Transaction details
}

// logFilteredEntry appends a transaction's log data to the log file, if it contains the filtered address.
func logFilteredEntry(txLog filteredTxLog) {
	if _, loaded := filteredCache.LoadOrStore(txLog.filteredAddress, struct{}{}); loaded {
		// If the address is already in the cache, do not log it again.
		return
	}

	// Send the log entry to the channel for processing.
	txLogChan <- txLog
}

// appendToFile appends a transaction's log data to the log file.
func appendToFile(txLog filteredTxLog) error {
	// Prepare log filename by appending FilteredReportFileName to the path.
	filename := filepath.Join(getDefaultPath(), filteredReportFileName)

	// Open the file in append mode. Create it if it doesn't exist.
	// Ensure that the file is only writable by the current user.
	file, err := os.OpenFile(filename, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write the formatted log to the file.
	_, err = file.Write(formatTxLog(txLog))

	return err
}

// formatTxLog formats a filteredTxLog struct into a single log entry string suitable for
// appending to the log file.
func formatTxLog(log filteredTxLog) []byte {
	var buf bytes.Buffer

	// Writing each log component to buffer
	buf.WriteString("timestamp: ")
	buf.WriteString(time.Now().Format(time.RFC3339)) // use RFC3339 standard formatting
	buf.WriteString(", filtered_address: ")
	buf.WriteString(log.filteredAddress)
	buf.WriteString(", tx_hash: ")
	buf.WriteString(log.transaction.Hash().Hex())
	buf.WriteString(", type: ")
	buf.WriteString(fmt.Sprintf("%d", log.transaction.Type())) // Properly formatting transaction type
	buf.WriteString(", from: ")
	buf.WriteString(log.from)

	if log.transaction.To() != nil {
		buf.WriteString(", to: ")
		buf.WriteString(log.transaction.To().Hex())
	}

	buf.WriteString(", value: ")
	buf.WriteString(log.transaction.Value().String())
	buf.WriteString(", nonce: ")
	buf.WriteString(fmt.Sprintf("%d", log.transaction.Nonce())) // Formatting numeric types
	buf.WriteString(", gas: ")
	buf.WriteString(fmt.Sprintf("%d", log.transaction.Gas()))
	buf.WriteString(", gas_price: ")
	buf.WriteString(log.transaction.GasPrice().String())
	buf.WriteByte('\n')

	return buf.Bytes()
}
