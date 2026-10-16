/*
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package dpop

import (
	"container/heap"
	"context"
	"log/slog"
	"sync"
	"time"
)

var (
	sharedReplayMu sync.Mutex
	sharedReplay   *replayStore
)

// sharedReplayStore returns the one replay store every policy instance on this
// gateway shares, resized to the latest configured bound.
func sharedReplayStore(maxSize int) *replayStore {
	sharedReplayMu.Lock()
	defer sharedReplayMu.Unlock()
	if sharedReplay == nil {
		sharedReplay = newReplayStore(maxSize)
	} else {
		sharedReplay.resize(maxSize)
	}
	return sharedReplay
}

// replayResult is the outcome of recording a proof identifier.
type replayResult int

const (
	replayStored      replayResult = iota // first use: recorded
	replaySeen                            // already recorded and not expired: a replay
	replayFull                            // the store is full of unexpired entries: nothing recorded
	replayUnavailable                     // the shared store cannot be reached: nothing recorded
)

// replayStore remembers accepted proof identifiers until they expire. It never
// drops an entry before its expiry: evicting a live entry to make room would let
// whoever fills the store replay the evicted proof (the flaw of CVE-2026-41707 in
// Spring Security). When it is full of live entries it refuses to record, and the
// caller refuses the request.
type replayStore struct {
	mu      sync.Mutex
	maxSize int
	entries map[[32]byte]time.Time
	expiry  expiryHeap // soonest expiry first
	warned  time.Time
}

// newReplayStore returns an empty store that holds at most maxSize live entries.
func newReplayStore(maxSize int) *replayStore {
	return &replayStore{maxSize: maxSize, entries: make(map[[32]byte]time.Time)}
}

// resize changes the bound; entries already stored are kept.
func (s *replayStore) resize(maxSize int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maxSize = maxSize
}

// checkAndStore records key until expiry. The lookup and the insert happen under
// one lock, so two concurrent copies of the same proof cannot both be stored.
func (s *replayStore) checkAndStore(_ context.Context, key [32]byte, expiry, now time.Time) replayResult {
	s.mu.Lock()
	defer s.mu.Unlock()

	if exp, ok := s.entries[key]; ok && exp.After(now) {
		return replaySeen
	}
	s.purgeExpired(now)
	if len(s.entries) >= s.maxSize {
		if now.Sub(s.warned) > time.Minute {
			s.warned = now
			slog.Warn("dpop: replay cache is full of unexpired proof identifiers; refusing DPoP requests until entries expire. Raise replayCacheMaxSize or lower proofMaxAge.",
				slog.Int("replayCacheMaxSize", s.maxSize))
		}
		return replayFull
	}
	s.entries[key] = expiry
	heap.Push(&s.expiry, expiryEntry{key: key, at: expiry})
	return replayStored
}

// purgeExpired drops every entry whose expiry has passed. A heap entry whose key
// was since re-recorded with a later expiry is skipped.
func (s *replayStore) purgeExpired(now time.Time) {
	for s.expiry.Len() > 0 && !s.expiry[0].at.After(now) {
		e := heap.Pop(&s.expiry).(expiryEntry)
		if exp, ok := s.entries[e.key]; ok && !exp.After(now) {
			delete(s.entries, e.key)
		}
	}
}

// size returns the number of entries currently held.
func (s *replayStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

type expiryEntry struct {
	key [32]byte
	at  time.Time
}

type expiryHeap []expiryEntry

// Len, Less, Swap, Push and Pop implement heap.Interface, ordering entries by expiry.
func (h expiryHeap) Len() int { return len(h) }

// Less orders entries soonest expiry first.
func (h expiryHeap) Less(i, j int) bool { return h[i].at.Before(h[j].at) }

// Swap exchanges two entries.
func (h expiryHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }

// Push appends an entry; use heap.Push.
func (h *expiryHeap) Push(x any) { *h = append(*h, x.(expiryEntry)) }

// Pop removes the last entry; use heap.Pop.
func (h *expiryHeap) Pop() any {
	old := *h
	e := old[len(old)-1]
	*h = old[:len(old)-1]
	return e
}
