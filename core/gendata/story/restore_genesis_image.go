package story

import (
	_ "embed"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"log"
)

func hexDataToImage(hexData, outputFilePath string) error {
	data, err := hex.DecodeString(hexData[2:])
	if err != nil {
		return fmt.Errorf("failed to decode hex data: %w", err)
	}

	if err := ioutil.WriteFile(outputFilePath, data, 0644); err != nil {
		return fmt.Errorf("failed to write image file: %w", err)
	}

	return nil
}

//go:embed genesis-extra-data.hex
var genesisExtraData string

// Using the genesis block data of the Story mainnet, you can reconstruct the genesis image.
//
// 1. Change the package name from `story` to `main`.
// 2. Run `go run core/gendata/story/restore_genesis_image.go` from the root.
// 3. The genesis image named `genesis-image.png` will be generated under `core/gendata/story`.

func main() {
	outputFilePath := "./core/gendata/story/genesis-image.png"

	if err := hexDataToImage(genesisExtraData, outputFilePath); err != nil {
		log.Fatalf("failed to restor image: %v", err)
	}
}
