package guardian

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

const (
	// filteredReportFileName represents the log filename for storing filtered transactions.
	filteredReportFileName = "filtered_report.log"
)

// filteredTxLog represents the details of a filtered transaction entry.
type filteredTxLog struct {
	filteredAddress string             // Address that is being filtered
	from            string             // Address that sent the transaction
	transaction     *types.Transaction // Transaction details
}

// logFilteredEntry appends a transaction's log data to the log file, if it contains the filtered address.
func logFilteredEntry(txLog filteredTxLog) error {
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
