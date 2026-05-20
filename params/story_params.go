package params

const (
	// Story Chain IDs
	IDStoryMainnet uint64 = 1514

	// Iliad Testnet.
	IDStoryIliad uint64 = 1513

	// Odyssey Testnet.
	IDStoryOdyssey uint64 = 1516

	// Aeneid Testnet.
	IDStoryAeneid uint64 = 1315

	// Local Testet.
	IDStoryLocal uint64 = 1511

	// Story protocol params
	DefaultBaseFeeChangeDenomStory = 24 // EIP1559 denominator for Story

	// DefaultMinBaseFeeStory is the floor for EIP-1559 base fee on Story chains
	// once the Amsterdam hardfork has activated. Initial value chosen for testnet
	// validation; final mainnet value is subject to foundation review.
	DefaultMinBaseFeeStory uint64 = 1 * GWei // 1 gwei
)
