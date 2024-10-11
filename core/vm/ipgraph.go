package vm

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const (
	ipGraphWriteGas        = 100
	ipGraphReadGas         = 10
	averageAncestorIpCount = 30
	averageParentIpCount   = 4
	intrinsicGas           = 100
)

var (
	royaltyPolicyKindLAP        = big.NewInt(0)
	royaltyPolicyKindLRP        = big.NewInt(1)
	ipGraphAddress              = common.HexToAddress("0x0000000000000000000000000000000000000101")
	aclAddress                  = common.HexToAddress("0x680E66e4c7Df9133a7AFC1ed091089B32b89C4ae")
	aclSlot                     = "af99b37fdaacca72ee7240cb1435cc9e498aee6ef4edc19c8cc0cd787f4e6800"
	addParentIpSelector         = crypto.Keccak256Hash([]byte("addParentIp(address,address[])")).Bytes()[:4]
	hasParentIpSelector         = crypto.Keccak256Hash([]byte("hasParentIp(address,address)")).Bytes()[:4]
	getParentIpsSelector        = crypto.Keccak256Hash([]byte("getParentIps(address)")).Bytes()[:4]
	getParentIpsCountSelector   = crypto.Keccak256Hash([]byte("getParentIpsCount(address)")).Bytes()[:4]
	getAncestorIpsSelector      = crypto.Keccak256Hash([]byte("getAncestorIps(address)")).Bytes()[:4]
	getAncestorIpsCountSelector = crypto.Keccak256Hash([]byte("getAncestorIpsCount(address)")).Bytes()[:4]
	hasAncestorIpsSelector      = crypto.Keccak256Hash([]byte("hasAncestorIp(address,address)")).Bytes()[:4]
	setRoyaltySelector          = crypto.Keccak256Hash([]byte("setRoyalty(address,address,uint256,uint256)")).Bytes()[:4]
	getRoyaltySelector          = crypto.Keccak256Hash([]byte("getRoyalty(address,address,uint256)")).Bytes()[:4]
	getRoyaltyStackSelector     = crypto.Keccak256Hash([]byte("getRoyaltyStack(address,uint256)")).Bytes()[:4]
)

type ipGraph struct{}

func (c *ipGraph) RequiredGas(input []byte) uint64 {
	if len(input) < 4 {
		return intrinsicGas
	}

	selector := input[:4]

	switch {
	case bytes.Equal(selector, addParentIpSelector):
		return ipGraphWriteGas
	case bytes.Equal(selector, hasParentIpSelector):
		return ipGraphReadGas * averageParentIpCount
	case bytes.Equal(selector, getParentIpsSelector):
		return ipGraphReadGas * averageParentIpCount
	case bytes.Equal(selector, getParentIpsCountSelector):
		return ipGraphReadGas
	case bytes.Equal(selector, getAncestorIpsSelector):
		return ipGraphReadGas * averageAncestorIpCount * 2
	case bytes.Equal(selector, getAncestorIpsCountSelector):
		return ipGraphReadGas * averageParentIpCount * 2
	case bytes.Equal(selector, hasAncestorIpsSelector):
		return ipGraphReadGas * averageAncestorIpCount * 2
	case bytes.Equal(selector, setRoyaltySelector):
		return ipGraphWriteGas
	case bytes.Equal(selector, getRoyaltySelector):
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 64, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount * 3)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount*2 + 2)
		} else {
			return intrinsicGas
		}
	case bytes.Equal(selector, getRoyaltyStackSelector):
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 32, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphReadGas * (averageParentIpCount + 1)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount * 2)
		} else {
			return intrinsicGas
		}
	default:
		return intrinsicGas
	}
}

func (c *ipGraph) Run(evm *EVM, input []byte) ([]byte, error) {
	log.Info("ipGraph.Run", "ipGraphAddress", ipGraphAddress, "input", input)

	if len(input) < 4 {
		return nil, fmt.Errorf("input too short")
	}

	selector := input[:4]
	args := input[4:]

	switch {
	case bytes.Equal(selector, addParentIpSelector):
		return c.addParentIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, hasParentIpSelector):
		return c.hasParentIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getParentIpsSelector):
		return c.getParentIps(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getParentIpsCountSelector):
		return c.getParentIpsCount(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getAncestorIpsSelector):
		return c.getAncestorIps(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getAncestorIpsCountSelector):
		return c.getAncestorIpsCount(args, evm, ipGraphAddress)
	case bytes.Equal(selector, hasAncestorIpsSelector):
		return c.hasAncestorIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, setRoyaltySelector):
		return c.setRoyalty(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getRoyaltySelector):
		return c.getRoyalty(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getRoyaltyStackSelector):
		return c.getRoyaltyStack(args, evm, ipGraphAddress)
	default:
		return nil, fmt.Errorf("unknown selector")
	}
}

func (c *ipGraph) isAllowed(evm *EVM) (bool, error) {
	slot := new(big.Int)
	slot.SetString(aclSlot, 16)
	isAllowedHash := evm.StateDB.GetState(aclAddress, common.BigToHash(slot))
	isAllowedBig := isAllowedHash.Big()

	log.Info("isAllowed", "aclAddress", aclAddress, "slot", slot, "isAllowedBig", isAllowedBig)
	if isAllowedBig.Cmp(big.NewInt(1)) == 0 {
		log.Info("isAllowed", "allowed", true)
		return true, nil
	}
	log.Info("isAllowed", "allowed", false)
	return false, nil
}

func (c *ipGraph) addParentIp(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to add parent IP")
	}

	log.Info("addParentIp", "input", input)
	if len(input) < 96 {
		return nil, fmt.Errorf("input too short for addParentIp")
	}
	ipId := common.BytesToAddress(input[0:32])
	log.Info("addParentIp", "ipId", ipId)
	parentCount := new(big.Int).SetBytes(getData(input, 64, 32))
	log.Info("addParentIp", "parentCount", parentCount)

	if len(input) < int(96+parentCount.Uint64()*32) {
		return nil, fmt.Errorf("input too short for parent IPs")
	}

	for i := 0; i < int(parentCount.Uint64()); i++ {
		parentIpId := common.BytesToAddress(input[96+i*32 : 96+(i+1)*32])
		index := uint64(i)
		slot := crypto.Keccak256Hash(ipId.Bytes()).Big()
		slot.Add(slot, new(big.Int).SetUint64(index))
		log.Info("addParentIp", "ipId", ipId, "parentIpId", parentIpId, "slot", slot)
		evm.StateDB.SetState(ipGraphAddress, common.BigToHash(slot), common.BytesToHash(parentIpId.Bytes()))
	}

	log.Info("addParentIp", "ipId", ipId, "parentCount", parentCount)
	evm.StateDB.SetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()), common.BigToHash(parentCount))

	return nil, nil
}

func (c *ipGraph) hasParentIp(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	if len(input) < 64 {
		return nil, fmt.Errorf("input too short for hasParentIp")
	}
	ipId := common.BytesToAddress(input[0:32])
	parentIpId := common.BytesToAddress(input[32:64])

	currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()))
	currentLength := currentLengthHash.Big()
	log.Info("hasParentIp", "ipId", ipId, "parentIpId", parentIpId, "currentLength", currentLength)
	for i := uint64(0); i < currentLength.Uint64(); i++ {
		slot := crypto.Keccak256Hash(ipId.Bytes()).Big()
		slot.Add(slot, new(big.Int).SetUint64(i))
		storedParent := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot))
		log.Info("hasParentIp", "storedParent", storedParent, "parentIpId", parentIpId)
		if common.BytesToAddress(storedParent.Bytes()) == parentIpId {
			log.Info("hasParentIp", "found", true)
			return common.LeftPadBytes([]byte{1}, 32), nil
		}
	}
	log.Info("hasParentIp", "found", false)
	return common.LeftPadBytes([]byte{0}, 32), nil
}

func (c *ipGraph) getParentIps(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getParentIps", "input", input)
	if len(input) < 32 {
		return nil, fmt.Errorf("input too short for getParentIps")
	}
	ipId := common.BytesToAddress(input[0:32])

	currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()))
	currentLength := currentLengthHash.Big()

	output := make([]byte, 64+currentLength.Uint64()*32)
	copy(output[0:32], common.BigToHash(new(big.Int).SetUint64(32)).Bytes())
	copy(output[32:64], common.BigToHash(currentLength).Bytes())

	for i := uint64(0); i < currentLength.Uint64(); i++ {
		slot := crypto.Keccak256Hash(ipId.Bytes()).Big()
		slot.Add(slot, new(big.Int).SetUint64(i))
		storedParent := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot))
		copy(output[64+i*32:], storedParent.Bytes())
	}
	log.Info("getParentIps", "output", output)
	return output, nil
}

func (c *ipGraph) getParentIpsCount(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getParentIpsCount", "input", input)
	if len(input) < 32 {
		return nil, fmt.Errorf("input too short for getParentIpsCount")
	}
	ipId := common.BytesToAddress(input[0:32])

	currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()))
	currentLength := currentLengthHash.Big()

	log.Info("getParentIpsCount", "ipId", ipId, "currentLength", currentLength)
	return common.BigToHash(currentLength).Bytes(), nil
}

func (c *ipGraph) getAncestorIps(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getAncestorIps", "input", input)
	if len(input) < 32 {
		return nil, fmt.Errorf("input too short for getAncestorIps")
	}
	ipId := common.BytesToAddress(input[0:32])
	ancestors := c.findAncestors(ipId, evm, ipGraphAddress)

	output := make([]byte, 64+len(ancestors)*32)
	copy(output[0:32], common.BigToHash(new(big.Int).SetUint64(32)).Bytes())
	copy(output[32:64], common.BigToHash(new(big.Int).SetUint64(uint64(len(ancestors)))).Bytes())

	i := 0
	for ancestor := range ancestors {
		copy(output[64+i*32:], common.LeftPadBytes(ancestor.Bytes(), 32))
		i++
	}

	log.Info("getAncestorIps", "output", output)
	return output, nil
}

func (c *ipGraph) getAncestorIpsCount(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getAncestorIpsCount", "input", input)
	if len(input) < 32 {
		return nil, fmt.Errorf("input too short for getAncestorIpsCount")
	}
	ipId := common.BytesToAddress(input[0:32])
	ancestors := c.findAncestors(ipId, evm, ipGraphAddress)

	count := new(big.Int).SetUint64(uint64(len(ancestors)))
	log.Info("getAncestorIpsCount", "ipId", ipId, "count", count)
	return common.BigToHash(count).Bytes(), nil
}

func (c *ipGraph) hasAncestorIp(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	if len(input) < 64 {
		return nil, fmt.Errorf("input too short for hasAncestorIp")
	}
	ipId := common.BytesToAddress(input[0:32])
	parentIpId := common.BytesToAddress(input[32:64])
	ancestors := c.findAncestors(ipId, evm, ipGraphAddress)

	if _, found := ancestors[parentIpId]; found {
		log.Info("hasAncestorIp", "found", true)
		return common.LeftPadBytes([]byte{1}, 32), nil
	}
	log.Info("hasAncestorIp", "found", false)
	return common.LeftPadBytes([]byte{0}, 32), nil
}

func (c *ipGraph) findAncestors(ipId common.Address, evm *EVM, ipGraphAddress common.Address) map[common.Address]struct{} {
	ancestors := make(map[common.Address]struct{})
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
		}
	}
	return ancestors
}

func (c *ipGraph) setRoyalty(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

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
	log.Info("setRoyalty", "ipId", ipId, "ipGraphAddress", ipGraphAddress, "parentIpId", parentIpId,
		"royaltyPolicyKind", royaltyPolicyKind, "royalty", royalty, "slot", slot)
	evm.StateDB.SetState(ipGraphAddress, common.BigToHash(slot), common.BigToHash(royalty))

	return nil, nil
}

func (c *ipGraph) getRoyalty(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getRoyalty", "ipGraphAddress", ipGraphAddress, "input", input)
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

	log.Info("getRoyalty", "ipId", ipId, "ancestorIpId", ancestorIpId, "ipGraphAddress", ipGraphAddress, "royaltyPolicyKind", royaltyPolicyKind, "totalRoyalty", totalRoyalty)
	return common.BigToHash(totalRoyalty).Bytes(), nil
}

func (c *ipGraph) getRoyaltyLap(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	log.Info("getRoyaltyLap", "ipId", ipId, "ancestorIpId", ancestorIpId, "ipGraphAddress", ipGraphAddress)
	ancestors := c.findAncestors(ipId, evm, ipGraphAddress)
	totalRoyalty := big.NewInt(0)
	for ancestor := range ancestors {
		log.Info("getRoyaltyLap", "found_ancestor", ancestor)
		if ancestor == ancestorIpId {
			// Traverse the graph to accumulate royalties
			totalRoyalty.Add(totalRoyalty, c.getRoyaltyLapForAncestor(ipId, ancestorIpId, evm, ipGraphAddress))
		}
	}
	return totalRoyalty
}

func (c *ipGraph) getRoyaltyLapForAncestor(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
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

func (c *ipGraph) getRoyaltyLrp(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	hundredPercent := big.NewInt(100000000) // 100% in the integer format

	royalty := make(map[common.Address]*big.Int)
	royalty[ipId] = hundredPercent

	topoOrder, allParents, err := c.topologicalSort(ipId, ancestorIpId, evm, ipGraphAddress)
	if err != nil {
		log.Error("Failed to perform topological sort", "error", err)
		return big.NewInt(0) // Return 0 if any error occurs
	}
	log.Info("getRoyaltyLrp", "topoOrder", topoOrder, "allParents", allParents)

	for i := len(topoOrder) - 1; i >= 0; i-- {
		node := topoOrder[i]
		log.Info("getRoyaltyLrp", "Processing node", node)
		// If we reached the ancestor IP, we can stop the calculation
		if node == ancestorIpId {
			log.Info("getRoyaltyLrp", "msg", "Ancestor IP reached, stopping royalty calculation", "ancestorIpId", ancestorIpId)
			break
		}

		currentRoyalty, exists := royalty[node]
		if !exists || currentRoyalty.Sign() == 0 {
			log.Info("getRoyaltyLrp", "msg", "Skipping node with no royalty", "node", node)
			continue // Skip if there's no royalty to distribute
		}

		parents := allParents[node]
		log.Info("getRoyaltyLrp", "parents", parents)
		for _, parentIpId := range parents {
			royaltySlot := crypto.Keccak256Hash(node.Bytes(), parentIpId.Bytes(), royaltyPolicyKindLRP.Bytes()).Big()
			royaltyHash := common.BigToHash(royaltySlot)
			parentRoyalty := evm.StateDB.GetState(ipGraphAddress, royaltyHash).Big()
			log.Info("getRoyaltyLrp", "parentIpId", parentIpId, "parentRoyalty", parentRoyalty)

			contribution := new(big.Int).Div(new(big.Int).Mul(currentRoyalty, parentRoyalty), hundredPercent)
			log.Info("getRoyaltyLrp", "contribution", contribution)

			if existingRoyalty, exists := royalty[parentIpId]; exists {
				royalty[parentIpId] = new(big.Int).Add(existingRoyalty, contribution)
				log.Info("getRoyaltyLrp", "msg", "Updated existing royalty", "parentIpId", parentIpId, "royalty", royalty[parentIpId])
			} else {
				royalty[parentIpId] = contribution
				log.Info("getRoyaltyLrp", "msg", "Added new royalty", "parentIpId", parentIpId, "royalty", royalty[parentIpId])
			}
		}
	}

	if result, exists := royalty[ancestorIpId]; exists {
		log.Info("getRoyaltyLrp", "msg", "Royalty for ancestor IP", "ancestorIpId", ancestorIpId, "royalty", result)
		return result
	}
	log.Info("getRoyaltyLrp", "msg", "Royalty for ancestor IP not found", "ancestorIpId", ancestorIpId)
	return big.NewInt(0)
}

func (c *ipGraph) topologicalSort(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) (
	[]common.Address, map[common.Address][]common.Address, error) {

	allParents := make(map[common.Address][]common.Address)
	visited := make(map[common.Address]bool)
	topoOrder := []common.Address{}
	stack := []common.Address{ipId}

	for len(stack) > 0 {
		log.Info("topologicalSort", "stack", stack)
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1] // pop from stack

		log.Info("topologicalSort", "pop current", current)
		log.Info("topologicalSort", "after pop stack", stack)
		log.Info("topologicalSort", "visited", visited)
		log.Info("topologicalSort", "topoOrder", topoOrder)

		if visited[current] {
			log.Info("topologicalSort", "msg", "current node already visited", "current", current)
			log.Info("topologicalSort", "msg", "adding to topoOrder", "current", current)
			topoOrder = append(topoOrder, current)
			log.Info("topologicalSort", "topoOrder", topoOrder)
			log.Info("topologicalSort", "msg", "Skipping visited node", "current", current)
			continue
		}
		visited[current] = true
		log.Info("topologicalSort", "visited", visited)
		stack = append(stack, current)
		log.Info("topologicalSort", "stack", stack)

		currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(current.Bytes()))
		currentLength := currentLengthHash.Big()
		log.Info("topologicalSort", "parentsLength", currentLength)
		for i := uint64(0); i < currentLength.Uint64(); i++ {
			slot := crypto.Keccak256Hash(current.Bytes()).Big()
			slot.Add(slot, new(big.Int).SetUint64(i))
			parentIpIdBytes := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot)).Bytes()
			parentIpId := common.BytesToAddress(parentIpIdBytes)
			allParents[current] = append(allParents[current], parentIpId)

			if !visited[parentIpId] {
				log.Info("topologicalSort", "msg", "Adding parent to stack", "parentIpId", parentIpId)
				stack = append(stack, parentIpId)
			}
		}
	}
	if !visited[ancestorIpId] {
		log.Info("Ancestor IP is not ancestor of child IP", "ancestorIpId", ancestorIpId, "childIpId", ipId)
		return []common.Address{}, map[common.Address][]common.Address{}, nil
	}
	return topoOrder, allParents, nil
}

func (c *ipGraph) getRoyaltyStack(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	log.Info("getRoyaltyStack", "ipGraphAddress", ipGraphAddress, "input", input)
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
	log.Info("getRoyaltyStack", "ipId", ipId, "ipGraphAddress", ipGraphAddress, "royaltyPolicyKind", royaltyPolicyKind, "totalRoyalty", totalRoyalty)
	return common.BigToHash(totalRoyalty).Bytes(), nil
}

func (c *ipGraph) getRoyaltyStackLap(ipId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
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

func (c *ipGraph) getRoyaltyStackLrp(ipId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
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
