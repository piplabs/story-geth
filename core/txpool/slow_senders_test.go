// Copyright 2025 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package txpool

import (
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

func TestSlowSendersAddHasAndEvictHook(t *testing.T) {
	s := NewSlowSenders(time.Hour)
	var evicted []common.Address
	s.SetEvictHook(func(a common.Address) { evicted = append(evicted, a) })

	addr := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	if s.Has(addr) {
		t.Fatal("empty set must not contain the address")
	}
	s.Add(addr)
	if !s.Has(addr) {
		t.Fatal("Has must be true right after Add")
	}
	if len(evicted) != 1 || evicted[0] != addr {
		t.Fatalf("evict hook should fire once with %s, got %v", addr, evicted)
	}
}

func TestSlowSendersTTLExpiry(t *testing.T) {
	s := NewSlowSenders(40 * time.Millisecond)
	addr := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	s.Add(addr)
	if !s.Has(addr) {
		t.Fatal("entry must be present before TTL")
	}
	time.Sleep(70 * time.Millisecond)
	if s.Has(addr) {
		t.Fatal("entry must expire after TTL")
	}
}
