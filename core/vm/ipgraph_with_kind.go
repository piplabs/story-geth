package vm

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

var (
	royaltyPolicyKindLAP            = big.NewInt(0)
	royaltyPolicyKindLRP            = big.NewInt(1)
	setRoyaltyWithKindSelector      = crypto.Keccak256Hash([]byte("setRoyalty(address,address,uint256,uint256)")).Bytes()[:4]
	getRoyaltyWithKindSelector      = crypto.Keccak256Hash([]byte("getRoyalty(address,address,uint256)")).Bytes()[:4]
	getRoyaltyStackWithKindSelector = crypto.Keccak256Hash([]byte("getRoyaltyStack(address,uint256)")).Bytes()[:4]
)

type ipGraphWithPolicyKind struct {
	ipGraph
	ipGraphDynamicGas
}

func (c *ipGraphWithPolicyKind) RequiredGas(input []byte) uint64 {
	log.Info("ipGraphWithPolicyKind.RequiredGas", "input", input)
	if len(input) < 4 {
		return 0
	}
	selector := input[:4]
	switch {
	case bytes.Equal(selector, addParentIpSelector):
		return c.ipGraphDynamicGas.RequiredGas(input)
	case bytes.Equal(selector, hasParentIpSelector):
		return c.ipGraphDynamicGas.RequiredGas(input)
	case bytes.Equal(selector, getParentIpsSelector):
		return c.ipGraphDynamicGas.RequiredGas(input)
	case bytes.Equal(selector, getParentIpsCountSelector):
		return c.ipGraphDynamicGas.RequiredGas(input)
	case bytes.Equal(selector, getAncestorIpsSelector):
		return c.ipGraphDynamicGas.RequiredGas(input)
	case bytes.Equal(selector, getAncestorIpsCountSelector):
		return c.ipGraphDynamicGas.RequiredGas(input)
	case bytes.Equal(selector, hasAncestorIpsSelector):
		return c.ipGraphDynamicGas.RequiredGas(input)
	case bytes.Equal(selector, setRoyaltyWithKindSelector):
		return ipGraphWriteGas
	case bytes.Equal(selector, getRoyaltyWithKindSelector):
		log.Info("getRoyaltyWithKindSelector")
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 64, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount * 3)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount*2 + 2)
		} else {
			return intrinsicGas
		}
	case bytes.Equal(selector, getRoyaltyStackWithKindSelector):
		log.Info("getRoyaltyStackWithKindSelector")
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 32, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphReadGas * (averageParentIpCount + 1)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount * 2)
		} else {
			return intrinsicGas
		}
	default:
		log.Info("ipGraphWithPolicyKind.RequiredGas", "selector", selector, "Default")
		return intrinsicGas
	}
}

func (c *ipGraphWithPolicyKind) Run(evm *EVM, input []byte) ([]byte, error) {
	ipGraphAddress := common.HexToAddress("0x000000000000000000000000000000000000001B")
	log.Info("ipGraph.Run", "ipGraphAddress", ipGraphAddress, "input", input)

	if len(input) < 4 {
		return nil, fmt.Errorf("input too short")
	}

	selector := input[:4]
	args := input[4:]

	switch {
	case bytes.Equal(selector, addParentIpSelector):
		return c.ipGraph.addParentIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, hasParentIpSelector):
		return c.ipGraph.hasParentIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getParentIpsSelector):
		return c.ipGraph.getParentIps(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getParentIpsCountSelector):
		return c.ipGraph.getParentIpsCount(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getAncestorIpsSelector):
		return c.ipGraph.getAncestorIps(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getAncestorIpsCountSelector):
		return c.ipGraph.getAncestorIpsCount(args, evm, ipGraphAddress)
	case bytes.Equal(selector, hasAncestorIpsSelector):
		return c.ipGraph.hasAncestorIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, setRoyaltyWithKindSelector):
		log.Info("ipGraph.Run.setRoyaltyWithKindSelector")
		return c.setRoyaltyWithKind(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getRoyaltyWithKindSelector):
		log.Info("ipGraph.Run.getRoyaltyWithKindSelector")
		return c.getRoyaltyWithKind(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getRoyaltyStackWithKindSelector):
		log.Info("ipGraph.Run.getRoyaltyStackWithKindSelector")
		return c.getRoyaltyStackWithKind(args, evm, ipGraphAddress)
	default:
		log.Info("ipGraph.Run.Default")
		return nil, fmt.Errorf("unknown selector")
	}
}


// Royalty has two kinds of policies: LAP and LRP.
func (c *ipGraphWithPolicyKind) setRoyaltyWithKind(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.ipGraph.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to set Royalty")
	}

	log.Info("setRoyalty", "ipGraphAddress", ipGraphAddress, "input", input)
	if len(input) < 96 {
		return nil, fmt.Errorf("input too short for setRoyalty")
	}
	ipId := common.BytesToAddress(input[0:32])
	parentIpId := common.BytesToAddress(input[32:64])
	royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 64, 32))
	royalty := new(big.Int).SetBytes(getData(input, 96, 32))
	slot := crypto.Keccak256Hash(ipId.Bytes(), parentIpId.Bytes(), royaltyPolicyKind.Bytes()).Big()
	log.Info("setRoyalty", "ipId", "ipGraphAddress", ipGraphAddress, ipId, "parentIpId", parentIpId,
		"royaltyPolicyKind", royaltyPolicyKind, "royalty", royalty, "slot", slot)
	evm.StateDB.SetState(ipGraphAddress, common.BigToHash(slot), common.BigToHash(royalty))

	return nil, nil
}

func (c *ipGraphWithPolicyKind) getRoyaltyStackWithKind(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getRoyaltyStackKind", "ipGraphAddress", ipGraphAddress, "input", input)
	totalRoyalty := big.NewInt(0)
	if len(input) < 32 {
		return nil, fmt.Errorf("input too short for getRoyaltyStack")
	}
	ipId := common.BytesToAddress(input[0:32])
	royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 32, 32))
	if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
		totalRoyalty = c.getRoyaltyStackLap(ipId, evm, ipGraphAddress)
	} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
		totalRoyalty = c.getRoyaltyStackLrp(ipId, evm, ipGraphAddress)
	} else {
		return nil, fmt.Errorf("unknown royalty policy kind")
	}
	log.Info("getRoyaltyStackKind", "ipId", ipId, "ipGraphAddress", ipGraphAddress, "royaltyPolicyKind", royaltyPolicyKind, "totalRoyalty", totalRoyalty)
	return common.BigToHash(totalRoyalty).Bytes(), nil
}

func (c *ipGraphWithPolicyKind) getRoyaltyWithKind(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getRoyaltyWithKind", "ipGraphAddress", ipGraphAddress, "input", input)
	if len(input) < 64 {
		return nil, fmt.Errorf("input too short for getRoyalty")
	}
	ipId := common.BytesToAddress(input[0:32])
	ancestorIpId := common.BytesToAddress(input[32:64])
	royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 64, 32))
	totalRoyalty := big.NewInt(0)
	if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
		totalRoyalty = c.getRoyaltyLap(ipId, ancestorIpId, evm, ipGraphAddress)
	} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
		totalRoyalty = c.getRoyaltyLrp(ipId, ancestorIpId, evm, ipGraphAddress)
	} else {
		return nil, fmt.Errorf("unknown royalty policy kind")
	}

	log.Info("getRoyaltyWithKind", "ipId", ipId, "ancestorIpId", ancestorIpId, "ipGraphAddress", ipGraphAddress, "royaltyPolicyKind", royaltyPolicyKind, "totalRoyalty", totalRoyalty)
	return common.BigToHash(totalRoyalty).Bytes(), nil
}

func (c *ipGraphWithPolicyKind) getRoyaltyStackLap(ipId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	log.Info("getRoyaltyStackLap", "ipGraphAddress", ipGraphAddress, "IP ID", ipId)
	ancestors := make(map[common.Address]struct{})
	totalRoyalty := big.NewInt(0)
	var stack []common.Address
	stack = append(stack, ipId)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(node.Bytes()))
		currentLength := currentLengthHash.Big()

		for i := uint64(0); i < currentLength.Uint64(); i++ {
			slot := crypto.Keccak256Hash(node.Bytes()).Big()
			slot.Add(slot, new(big.Int).SetUint64(i))
			storedParent := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot))
			parentIpId := common.BytesToAddress(storedParent.Bytes())

			if _, found := ancestors[parentIpId]; !found {
				ancestors[parentIpId] = struct{}{}
				stack = append(stack, parentIpId)
			}

			royaltySlot := crypto.Keccak256Hash(node.Bytes(), parentIpId.Bytes(), royaltyPolicyKindLAP.Bytes()).Big()
			royalty := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(royaltySlot)).Big()
			totalRoyalty.Add(totalRoyalty, royalty)
		}
	}
	return totalRoyalty
}

func (c *ipGraphWithPolicyKind) getRoyaltyStackLrp(ipId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	log.Info("getRoyaltyStackLrp", "ipGraphAddress", ipGraphAddress, "IP ID", ipId)
	totalRoyalty := big.NewInt(0)
	currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()))
	currentLength := currentLengthHash.Big()

	for i := uint64(0); i < currentLength.Uint64(); i++ {
		slot := crypto.Keccak256Hash(ipId.Bytes()).Big()
		slot.Add(slot, new(big.Int).SetUint64(i))
		storedParent := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot))
		parentIpId := common.BytesToAddress(storedParent.Bytes())
		royaltySlot := crypto.Keccak256Hash(ipId.Bytes(), parentIpId.Bytes(), royaltyPolicyKindLRP.Bytes()).Big()
		royalty := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(royaltySlot)).Big()
		totalRoyalty.Add(totalRoyalty, royalty)
	}
	return totalRoyalty
}

func (c *ipGraphWithPolicyKind) getRoyaltyLap(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	log.Info("getRoyaltyLap", "ipId", ipId, "ancestorIpId", ancestorIpId, "ipGraphAddress", ipGraphAddress)
	ancestors := c.ipGraph.findAncestors(ipId, evm, ipGraphAddress)
	totalRoyalty := big.NewInt(0)
	for ancestor := range ancestors {
		if ancestor == ancestorIpId {
			// Traverse the graph to accumulate royalties
			totalRoyalty.Add(totalRoyalty, c.getRoyaltyLapForAncestor(ipId, ancestorIpId, evm, ipGraphAddress))
		}
	}
	return totalRoyalty
}

func (c *ipGraphWithPolicyKind) getRoyaltyLrp(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	log.Info("getRoyaltyLrp", "ipId", ipId, "ancestorIpId", ancestorIpId)

	// Constants
	hundredPercent := big.NewInt(100000000) // royalties are represented in basis points (1% = 1000000)

	// Initialize result to accumulate the final royalty percentage
	result := big.NewInt(0)

	// Clear any previous state related to ancestors
	ancestorIps := make(map[common.Address]struct{})
	childMap := make(map[common.Address]common.Address)

	// Stack for DFS traversal
	var stack []common.Address
	stack = append(stack, ipId)

	// Perform DFS to find the path from ipId to ancestorIpId
	for len(stack) > 0 {
		currentIpId := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// If we've reached the ancestor, stop the search
		if currentIpId == ancestorIpId {
			break
		}

		// Get the number of parent IPs for the current node
		currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(currentIpId.Bytes()))
		currentLength := currentLengthHash.Big()

		// If there are no parent IPs, continue to the next node
		if currentLength.Uint64() == 0 {
			continue
		}

		// Traverse all parent IPs
		for i := uint64(0); i < currentLength.Uint64(); i++ {
			slot := crypto.Keccak256Hash(currentIpId.Bytes()).Big()
			slot.Add(slot, new(big.Int).SetUint64(i))
			storedParent := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot))
			parentIpId := common.BytesToAddress(storedParent.Bytes())

			// Map the parent to the child to reconstruct the path later
			childMap[parentIpId] = currentIpId

			// If this parent hasn't been visited, add it to the stack
			if _, found := ancestorIps[parentIpId]; !found {
				ancestorIps[parentIpId] = struct{}{}
				stack = append(stack, parentIpId)
			}
		}
	}

	// Reconstruct the path from ipId to ancestorIpId and calculate royalty
	currentIpId := ancestorIpId
	var lrpQueue []common.Address

	// Traverse the childMap to find the full path from ipId to ancestorIpId
	for currentIpId != ipId {
		lrpQueue = append(lrpQueue, currentIpId)
		currentIpId = childMap[currentIpId]
	}

	// If a path is found, calculate the royalty along the path
	currentIpId = ipId
	if len(lrpQueue) > 0 {
		// Pop the first parent from the queue and calculate initial royalty
		parentIpId := lrpQueue[len(lrpQueue)-1]
		lrpQueue = lrpQueue[:len(lrpQueue)-1]

		royaltySlot := crypto.Keccak256Hash(currentIpId.Bytes(), parentIpId.Bytes(), royaltyPolicyKindLRP.Bytes()).Big()
		initialRoyalty := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(royaltySlot)).Big()
		result.Set(initialRoyalty)
		currentIpId = parentIpId

		// Multiply royalties along the remaining path
		for len(lrpQueue) > 0 {
			parentIpId = lrpQueue[len(lrpQueue)-1]
			lrpQueue = lrpQueue[:len(lrpQueue)-1]

			royaltySlot = crypto.Keccak256Hash(currentIpId.Bytes(), parentIpId.Bytes(), royaltyPolicyKindLRP.Bytes()).Big()
			nextRoyalty := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(royaltySlot)).Big()

			// Multiply the result by the next royalty and divide by 10000 (assuming basis points)
			result.Mul(result, nextRoyalty)
			result.Div(result, hundredPercent)

			// Move to the next parent
			currentIpId = parentIpId
		}
	}

	log.Info("getRoyaltyLrp: totalRoyalty", "totalRoyalty", result)
	return result
}

func (c *ipGraphWithPolicyKind) getRoyaltyLapForAncestor(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	ancestors := make(map[common.Address]struct{})
	totalRoyalty := big.NewInt(0)
	var stack []common.Address
	stack = append(stack, ipId)
	for len(stack) > 0 {
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(node.Bytes()))
		currentLength := currentLengthHash.Big()

		for i := uint64(0); i < currentLength.Uint64(); i++ {
			slot := crypto.Keccak256Hash(node.Bytes()).Big()
			slot.Add(slot, new(big.Int).SetUint64(i))
			storedParent := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot))
			parentIpId := common.BytesToAddress(storedParent.Bytes())

			if _, found := ancestors[parentIpId]; !found {
				ancestors[parentIpId] = struct{}{}
				stack = append(stack, parentIpId)
			}

			if parentIpId == ancestorIpId {
				royaltySlot := crypto.Keccak256Hash(node.Bytes(), ancestorIpId.Bytes(), royaltyPolicyKindLAP.Bytes()).Big()
				royalty := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(royaltySlot)).Big()
				totalRoyalty.Add(totalRoyalty, royalty)
			}
		}
	}
	return totalRoyalty
}
