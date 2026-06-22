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
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// SlowSenders is a node-local TTL denylist of transaction senders whose calls the
// block-building watchdog measured to exceed the per-tx execution budget. Keying on
// the signer (not the recipient) keeps the effect to addresses the attacker controls
// and never censors a shared contract. Entries expire so a sender is re-evaluated,
// and the whole set is dropped on restart.
type SlowSenders struct {
	mu    sync.Mutex
	ttl   time.Duration
	m     map[common.Address]time.Time
	evict func(common.Address)
}

func NewSlowSenders(ttl time.Duration) *SlowSenders {
	return &SlowSenders{ttl: ttl, m: make(map[common.Address]time.Time)}
}

// SetEvictHook registers a callback invoked, outside the internal lock, whenever a
// sender is added, so the owning pool can drop that sender's pooled transactions.
func (s *SlowSenders) SetEvictHook(fn func(common.Address)) {
	s.mu.Lock()
	s.evict = fn
	s.mu.Unlock()
}

func (s *SlowSenders) Add(addr common.Address) {
	now := time.Now()
	s.mu.Lock()
	for k, exp := range s.m {
		if now.After(exp) {
			delete(s.m, k)
		}
	}
	s.m[addr] = now.Add(s.ttl)
	evict := s.evict
	s.mu.Unlock()

	if evict != nil {
		evict(addr)
	}
}

func (s *SlowSenders) Has(addr common.Address) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	exp, ok := s.m[addr]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(s.m, addr)
		return false
	}
	return true
}
