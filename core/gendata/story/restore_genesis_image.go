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

func main() {
	outputFilePath := "./core/gendata/story/genesis-image.png"

	if err := hexDataToImage(genesisExtraData, outputFilePath); err != nil {
		log.Fatalf("failed to restor image: %v", err)
	}
}
