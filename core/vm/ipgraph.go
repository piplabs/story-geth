package vm

import (
	"bytes"
	"fmt"
	"math/big"
	"sort"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

const (
	ipGraphWriteGas        = 100
	ipGraphReadGas         = 10
	averageAncestorIpCount = 30
	averageParentIpCount   = 4
	intrinsicGas           = 1000
	ipGraphExternalReadGas = 2100
)

var (
	royaltyPolicyKindLAP           = big.NewInt(0)         // Liquid Absolute Percentage (LAP) Royalty Policy
	royaltyPolicyKindLRP           = big.NewInt(1)         // Liquid Relative Percentage (LRP) Royalty Policy
	hundredPercent                 = big.NewInt(100000000) // 100% in the integer format
	ipGraphAddress                 = common.HexToAddress("0x0000000000000000000000000000000000000101")
	aclAddress                     = common.HexToAddress("0x1640A22a8A086747cD377b73954545e2Dfcc9Cad")
	aclSlot                        = "af99b37fdaacca72ee7240cb1435cc9e498aee6ef4edc19c8cc0cd787f4e6800"
	addParentIpSelector            = crypto.Keccak256Hash([]byte("addParentIp(address,address[])")).Bytes()[:4]
	hasParentIpSelector            = crypto.Keccak256Hash([]byte("hasParentIp(address,address)")).Bytes()[:4]
	getParentIpsSelector           = crypto.Keccak256Hash([]byte("getParentIps(address)")).Bytes()[:4]
	getParentIpsCountSelector      = crypto.Keccak256Hash([]byte("getParentIpsCount(address)")).Bytes()[:4]
	getAncestorIpsSelector         = crypto.Keccak256Hash([]byte("getAncestorIps(address)")).Bytes()[:4]
	getAncestorIpsCountSelector    = crypto.Keccak256Hash([]byte("getAncestorIpsCount(address)")).Bytes()[:4]
	hasAncestorIpsSelector         = crypto.Keccak256Hash([]byte("hasAncestorIp(address,address)")).Bytes()[:4]
	setRoyaltySelector             = crypto.Keccak256Hash([]byte("setRoyalty(address,address,uint256,uint256)")).Bytes()[:4]
	getRoyaltySelector             = crypto.Keccak256Hash([]byte("getRoyalty(address,address,uint256)")).Bytes()[:4]
	getRoyaltyStackSelector        = crypto.Keccak256Hash([]byte("getRoyaltyStack(address,uint256)")).Bytes()[:4]
	hasParentIpExtSelector         = crypto.Keccak256Hash([]byte("hasParentIpExt(address,address)")).Bytes()[:4]
	getParentIpsExtSelector        = crypto.Keccak256Hash([]byte("getParentIpsExt(address)")).Bytes()[:4]
	getParentIpsCountExtSelector   = crypto.Keccak256Hash([]byte("getParentIpsCountExt(address)")).Bytes()[:4]
	getAncestorIpsExtSelector      = crypto.Keccak256Hash([]byte("getAncestorIpsExt(address)")).Bytes()[:4]
	getAncestorIpsCountExtSelector = crypto.Keccak256Hash([]byte("getAncestorIpsCountExt(address)")).Bytes()[:4]
	hasAncestorIpsExtSelector      = crypto.Keccak256Hash([]byte("hasAncestorIpExt(address,address)")).Bytes()[:4]
	getRoyaltyExtSelector          = crypto.Keccak256Hash([]byte("getRoyaltyExt(address,address,uint256)")).Bytes()[:4]
	getRoyaltyStackExtSelector     = crypto.Keccak256Hash([]byte("getRoyaltyStackExt(address,uint256)")).Bytes()[:4]
	MaxUint32                      = new(big.Int).SetUint64(uint64(^uint32(0)))
)

type ipGraph struct{}

func (c *ipGraph) RequiredGas(input []byte) uint64 {
	// Smart contract function's selector is the first 4 bytes of the input
	if len(input) < 4 {
		return intrinsicGas
	}

	selector := input[:4]

	switch {
	case bytes.Equal(selector, addParentIpSelector):
		args := input[4:]
		parentCount := new(big.Int).SetBytes(getData(args, 64, 32))
		return intrinsicGas + (ipGraphWriteGas * parentCount.Uint64())
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
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 64+4, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount * 3)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount*2 + 2)
		} else {
			return intrinsicGas
		}
	case bytes.Equal(selector, getRoyaltyStackSelector):
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 32+4, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphReadGas * (averageParentIpCount + 1)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphReadGas * (averageAncestorIpCount * 2)
		} else {
			return intrinsicGas
		}
	case bytes.Equal(selector, hasParentIpExtSelector):
		return ipGraphExternalReadGas * averageParentIpCount
	case bytes.Equal(selector, getParentIpsExtSelector):
		return ipGraphExternalReadGas * averageParentIpCount
	case bytes.Equal(selector, getParentIpsCountExtSelector):
		return ipGraphExternalReadGas
	case bytes.Equal(selector, getAncestorIpsExtSelector):
		return ipGraphExternalReadGas * averageAncestorIpCount * 2
	case bytes.Equal(selector, getAncestorIpsCountExtSelector):
		return ipGraphExternalReadGas * averageParentIpCount * 2
	case bytes.Equal(selector, hasAncestorIpsExtSelector):
		return ipGraphExternalReadGas * averageAncestorIpCount * 2
	case bytes.Equal(selector, getRoyaltyExtSelector):
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 64+4, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphExternalReadGas * (averageAncestorIpCount * 3)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphExternalReadGas * (averageAncestorIpCount*2 + 2)
		} else {
			return intrinsicGas
		}
	case bytes.Equal(selector, getRoyaltyStackExtSelector):
		royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 32+4, 32))
		if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
			return ipGraphExternalReadGas * (averageParentIpCount + 1)
		} else if royaltyPolicyKind.Cmp(royaltyPolicyKindLRP) == 0 {
			return ipGraphExternalReadGas * (averageAncestorIpCount * 2)
		} else {
			return intrinsicGas
		}
	default:
		return intrinsicGas
	}
}

func (c *ipGraph) Run(evm *EVM, input []byte) ([]byte, error) {
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
	case bytes.Equal(selector, hasParentIpExtSelector):
		return c.hasParentIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getParentIpsExtSelector):
		return c.getParentIps(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getParentIpsCountExtSelector):
		return c.getParentIpsCount(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getAncestorIpsExtSelector):
		return c.getAncestorIps(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getAncestorIpsCountExtSelector):
		return c.getAncestorIpsCount(args, evm, ipGraphAddress)
	case bytes.Equal(selector, hasAncestorIpsExtSelector):
		return c.hasAncestorIp(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getRoyaltyExtSelector):
		return c.getRoyalty(args, evm, ipGraphAddress)
	case bytes.Equal(selector, getRoyaltyStackExtSelector):
		return c.getRoyaltyStack(args, evm, ipGraphAddress)
	default:
		return nil, fmt.Errorf("unknown selector")
	}
}

func (c *ipGraph) isAllowed(evm *EVM) (bool, error) {
	slot := new(big.Int)
	slot.SetString(aclSlot, 16)
	isAllowedHash := evm.StateDB.GetTransientState(aclAddress, common.BigToHash(slot))
	isAllowedBig := isAllowedHash.Big()

	if isAllowedBig.Cmp(big.NewInt(1)) == 0 {
		return true, nil
	}
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

	if evm.currentPrecompileCallType != CALL {
		return nil, fmt.Errorf("addParentIp can only be called with CALL, not %v", evm.currentPrecompileCallType)
	}

	if len(input) < 96 {
		return nil, fmt.Errorf("input too short for addParentIp")
	}
	ipId := common.BytesToAddress(input[0:32])
	parentCount := new(big.Int).SetBytes(getData(input, 64, 32))

	if len(input) != int(96+parentCount.Uint64()*32) {
		return nil, fmt.Errorf("input length does not match parent count")
	}

	for i := 0; i < int(parentCount.Uint64()); i++ {
		parentIpId := common.BytesToAddress(input[96+i*32 : 96+(i+1)*32])
		index := uint64(i)
		slot := crypto.Keccak256Hash(ipId.Bytes()).Big()
		slot.Add(slot, new(big.Int).SetUint64(index))
		evm.StateDB.SetState(ipGraphAddress, common.BigToHash(slot), common.BytesToHash(parentIpId.Bytes()))
	}

	evm.StateDB.SetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()), common.BigToHash(parentCount))

	return nil, nil
}

func (c *ipGraph) hasParentIp(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to query hasParentIp")
	}

	if len(input) != 64 {
		return nil, fmt.Errorf("input too short for hasParentIp")
	}
	ipId := common.BytesToAddress(input[0:32])
	parentIpId := common.BytesToAddress(input[32:64])

	currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()))
	currentLength := currentLengthHash.Big()
	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("hasParentIp cannot be called with DELEGATECALL")
	}
	for i := uint64(0); i < currentLength.Uint64(); i++ {
		slot := crypto.Keccak256Hash(ipId.Bytes()).Big()
		slot.Add(slot, new(big.Int).SetUint64(i))
		storedParent := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot))
		if common.BytesToAddress(storedParent.Bytes()) == parentIpId {
			return common.LeftPadBytes([]byte{1}, 32), nil
		}
	}
	return common.LeftPadBytes([]byte{0}, 32), nil
}

func (c *ipGraph) getParentIps(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to query getParentIps")
	}

	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("getParentIps cannot be called with DELEGATECALL")
	}
	if len(input) != 32 {
		return nil, fmt.Errorf("inputs too short for getParentIps")
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
	return output, nil
}

func (c *ipGraph) getParentIpsCount(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to query parent Ips count")
	}

	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("getParentIpsCount cannot be called with DELEGATECALL")
	}
	if len(input) != 32 {
		return nil, fmt.Errorf("input too short for getParentIpsCount")
	}
	ipId := common.BytesToAddress(input[0:32])

	currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(ipId.Bytes()))
	currentLength := currentLengthHash.Big()

	return common.BigToHash(currentLength).Bytes(), nil
}

func (c *ipGraph) getAncestorIps(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to query getAncestorIps")
	}

	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("getAncestorIps cannot be called with DELEGATECALL")
	}
	if len(input) != 32 {
		return nil, fmt.Errorf("input too short for getAncestorIps")
	}
	ipId := common.BytesToAddress(input[0:32])
	ancestorsMap := c.findAncestors(ipId, evm, ipGraphAddress)

	// Convert map keys to a sorted slice for stable ordering results
	ancestors := make([]common.Address, 0, len(ancestorsMap))
	for ancestor := range ancestorsMap {
		ancestors = append(ancestors, ancestor)
	}
	sort.Slice(ancestors, func(i, j int) bool {
		return bytes.Compare(ancestors[i].Bytes(), ancestors[j].Bytes()) < 0
	})

	output := make([]byte, 64+len(ancestors)*32)
	copy(output[0:32], common.BigToHash(new(big.Int).SetUint64(32)).Bytes())
	copy(output[32:64], common.BigToHash(new(big.Int).SetUint64(uint64(len(ancestors)))).Bytes())

	for i, ancestor := range ancestors {
		copy(output[64+i*32:], common.LeftPadBytes(ancestor.Bytes(), 32))
	}

	return output, nil
}

func (c *ipGraph) getAncestorIpsCount(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to query getAncestorIpsCount")
	}

	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("getAncestorIpsCount cannot be called with DELEGATECALL")
	}
	if len(input) != 32 {
		return nil, fmt.Errorf("input too short for getAncestorIpsCount")
	}
	ipId := common.BytesToAddress(input[0:32])
	ancestors := c.findAncestors(ipId, evm, ipGraphAddress)

	count := new(big.Int).SetUint64(uint64(len(ancestors)))
	return common.BigToHash(count).Bytes(), nil
}

func (c *ipGraph) hasAncestorIp(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("hasAncestorIp cannot be called with DELEGATECALL")
	}
	if len(input) != 64 {
		return nil, fmt.Errorf("input too short for hasAncestorIp")
	}
	ipId := common.BytesToAddress(input[0:32])
	parentIpId := common.BytesToAddress(input[32:64])
	ancestors := c.findAncestors(ipId, evm, ipGraphAddress)

	if _, found := ancestors[parentIpId]; found {
		return common.LeftPadBytes([]byte{1}, 32), nil
	}
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

	if evm.currentPrecompileCallType != CALL {
		return nil, fmt.Errorf("setRoyalty can only be called with CALL, not %v", evm.currentPrecompileCallType)
	}

	if len(input) != 128 {
		return nil, fmt.Errorf("input too short for setRoyalty")
	}
	ipId := common.BytesToAddress(input[0:32])
	parentIpId := common.BytesToAddress(input[32:64])
	royaltyPolicyKind := new(big.Int).SetBytes(getData(input, 64, 32))
	royalty := new(big.Int).SetBytes(getData(input, 96, 32))
	// Check if royalty value fits in uint32
	if royalty.Cmp(MaxUint32) > 0 {
		return nil, fmt.Errorf("royalty value exceeds uint32 range")
	}

	slot := crypto.Keccak256Hash(ipId.Bytes(), parentIpId.Bytes(), royaltyPolicyKind.Bytes()).Big()
	evm.StateDB.SetState(ipGraphAddress, common.BigToHash(slot), common.BigToHash(royalty))

	if royaltyPolicyKind.Cmp(royaltyPolicyKindLAP) == 0 {
		slot = crypto.Keccak256Hash(parentIpId.Bytes(), royaltyPolicyKind.Bytes(), []byte("royaltyStack")).Big()
		parentRoyaltyStack := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot)).Big()
		slot = crypto.Keccak256Hash(ipId.Bytes(), royaltyPolicyKind.Bytes(), []byte("royaltyStack")).Big()
		royaltyStack := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot)).Big()
		royaltyStack.Add(royaltyStack, parentRoyaltyStack)
		royaltyStack.Add(royaltyStack, royalty)
		slot = crypto.Keccak256Hash(ipId.Bytes(), royaltyPolicyKind.Bytes(), []byte("royaltyStack")).Big()
		evm.StateDB.SetState(ipGraphAddress, common.BigToHash(slot), common.BigToHash(royaltyStack))
	}
	return nil, nil
}

func (c *ipGraph) getRoyalty(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to query getRoyalty")
	}

	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("getRoyalty cannot be called with DELEGATECALL")
	}
	if len(input) != 96 {
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

	// Check if royalty value fits in uint32
	if totalRoyalty.Cmp(MaxUint32) > 0 {
		return nil, fmt.Errorf("royalty value exceeds uint32 range")
	}
	return common.BigToHash(totalRoyalty).Bytes(), nil
}

func (c *ipGraph) getRoyaltyLap(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	royalty := make(map[common.Address]*big.Int)
	pathCount := make(map[common.Address]*big.Int)
	royalty[ipId] = hundredPercent
	pathCount[ipId] = big.NewInt(1)

	topoOrder, allParents, err := c.topologicalSort(ipId, ancestorIpId, evm, ipGraphAddress)
	if err != nil {
		log.Error("Failed to perform topological sort", "error", err)
		return big.NewInt(0) // Return 0 if any error occurs
	}

	for i := len(topoOrder) - 1; i >= 0; i-- {
		node := topoOrder[i]
		// If we reached the ancestor IP, we can stop the calculation
		if node == ancestorIpId {
			break
		}

		parents := allParents[node]
		for _, parentIpId := range parents {
			royaltySlot := crypto.Keccak256Hash(node.Bytes(), parentIpId.Bytes(), royaltyPolicyKindLAP.Bytes()).Big()
			royaltyHash := common.BigToHash(royaltySlot)
			parentRoyalty := evm.StateDB.GetState(ipGraphAddress, royaltyHash).Big()

			contribution := pathCount[node]

			if existingPathCount, exists := pathCount[parentIpId]; exists {
				pathCount[parentIpId] = new(big.Int).Add(existingPathCount, contribution)
			} else {
				pathCount[parentIpId] = contribution
			}

			if existingRoyalty, exists := royalty[parentIpId]; exists {
				royalty[parentIpId] = new(big.Int).Add(existingRoyalty, new(big.Int).Mul(contribution, parentRoyalty))
			} else {
				royalty[parentIpId] = new(big.Int).Mul(contribution, parentRoyalty)
			}
		}
	}

	if result, exists := royalty[ancestorIpId]; exists {
		return result
	}
	return big.NewInt(0)
}

func (c *ipGraph) getRoyaltyLrp(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	royalty := make(map[common.Address]*big.Int)
	royalty[ipId] = hundredPercent

	topoOrder, allParents, err := c.topologicalSort(ipId, ancestorIpId, evm, ipGraphAddress)
	if err != nil {
		log.Error("Failed to perform topological sort", "error", err)
		return big.NewInt(0) // Return 0 if any error occurs
	}

	for i := len(topoOrder) - 1; i >= 0; i-- {
		node := topoOrder[i]
		// If we reached the ancestor IP, we can stop the calculation
		if node == ancestorIpId {
			break
		}

		currentRoyalty, exists := royalty[node]
		if !exists || currentRoyalty.Sign() == 0 {
			continue // Skip if there's no royalty to distribute
		}

		parents := allParents[node]
		for _, parentIpId := range parents {
			royaltySlot := crypto.Keccak256Hash(node.Bytes(), parentIpId.Bytes(), royaltyPolicyKindLRP.Bytes()).Big()
			royaltyHash := common.BigToHash(royaltySlot)
			parentRoyalty := evm.StateDB.GetState(ipGraphAddress, royaltyHash).Big()

			contribution := new(big.Int).Div(new(big.Int).Mul(currentRoyalty, parentRoyalty), hundredPercent)

			if existingRoyalty, exists := royalty[parentIpId]; exists {
				royalty[parentIpId] = new(big.Int).Add(existingRoyalty, contribution)
			} else {
				royalty[parentIpId] = contribution
			}
		}
	}

	if result, exists := royalty[ancestorIpId]; exists {
		return result
	}
	return big.NewInt(0)
}

func (c *ipGraph) topologicalSort(ipId, ancestorIpId common.Address, evm *EVM, ipGraphAddress common.Address) (
	[]common.Address, map[common.Address][]common.Address, error) {

	allParents := make(map[common.Address][]common.Address)
	visited := make(map[common.Address]bool)
	inTopoOrder := make(map[common.Address]bool)
	topoOrder := []common.Address{}
	stack := []common.Address{ipId}

	for len(stack) > 0 {
		current := stack[len(stack)-1]
		stack = stack[:len(stack)-1] // pop from stack

		if visited[current] {
			if !inTopoOrder[current] {
				topoOrder = append(topoOrder, current)
				inTopoOrder[current] = true
			}
			continue
		}
		visited[current] = true
		stack = append(stack, current)

		currentLengthHash := evm.StateDB.GetState(ipGraphAddress, common.BytesToHash(current.Bytes()))
		currentLength := currentLengthHash.Big()
		for i := uint64(0); i < currentLength.Uint64(); i++ {
			slot := crypto.Keccak256Hash(current.Bytes()).Big()
			slot.Add(slot, new(big.Int).SetUint64(i))
			parentIpIdBytes := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot)).Bytes()
			parentIpId := common.BytesToAddress(parentIpIdBytes)
			allParents[current] = append(allParents[current], parentIpId)

			if !visited[parentIpId] {
				stack = append(stack, parentIpId)
			}
		}
	}
	if !visited[ancestorIpId] {
		return []common.Address{}, map[common.Address][]common.Address{}, nil
	}
	return topoOrder, allParents, nil
}

func (c *ipGraph) getRoyaltyStack(input []byte, evm *EVM, ipGraphAddress common.Address) ([]byte, error) {
	allowed, err := c.isAllowed(evm)

	if err != nil {
		return nil, err
	}

	if !allowed {
		return nil, fmt.Errorf("caller not allowed to query getRoyaltyStack")
	}

	if evm.currentPrecompileCallType == DELEGATECALL {
		return nil, fmt.Errorf("getRoyaltyStack cannot be called with DELEGATECALL")
	}
	totalRoyalty := big.NewInt(0)
	if len(input) != 64 {
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
	return common.BigToHash(totalRoyalty).Bytes(), nil
}

func (c *ipGraph) getRoyaltyStackLap(ipId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
	slot := crypto.Keccak256Hash(ipId.Bytes(), royaltyPolicyKindLAP.Bytes(), []byte("royaltyStack")).Big()
	royaltyStack := evm.StateDB.GetState(ipGraphAddress, common.BigToHash(slot)).Big()
	return royaltyStack
}

func (c *ipGraph) getRoyaltyStackLrp(ipId common.Address, evm *EVM, ipGraphAddress common.Address) *big.Int {
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
