/*
 *  Copyright (c) 2025, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package semantictoolfiltering

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// Cache limits configuration
const (
	DefaultMaxAPIs         = 2  // Maximum number of APIs to store in cache
	DefaultMaxToolsPerAPI  = 5 // Maximum number of tools per API
)

// EmbeddingEntry stores the tool name, its embedding vector, and last access time
type EmbeddingEntry struct {
	Name         string
	Embedding    []float32
	LastAccessed time.Time
}

// APICache wraps the tool cache with API-level metadata
type APICache struct {
	Tools        map[string]*EmbeddingEntry // Key: SHA-256 hash of tool description
	LastAccessed time.Time
}

// APIEmbeddingCache stores embeddings for a specific API
// Key: SHA-256 hash of tool description → Value: EmbeddingEntry
type APIEmbeddingCache map[string]*EmbeddingEntry

// EmbeddingCacheStore is a global singleton for storing embeddings per API
type EmbeddingCacheStore struct {
	mu              sync.RWMutex
	cache           map[string]*APICache // Key: API ID → Value: APICache
	maxAPIs         int
	maxToolsPerAPI  int
}

// Singleton instance for EmbeddingCacheStore
var (
	embeddingCacheInstance *EmbeddingCacheStore
	embeddingCacheOnce     sync.Once
)

// GetEmbeddingCacheStoreInstance returns the global singleton instance
func GetEmbeddingCacheStoreInstance() *EmbeddingCacheStore {
	embeddingCacheOnce.Do(func() {
		embeddingCacheInstance = &EmbeddingCacheStore{
			cache:          make(map[string]*APICache),
			maxAPIs:        DefaultMaxAPIs,
			maxToolsPerAPI: DefaultMaxToolsPerAPI,
		}
	})
	return embeddingCacheInstance
}

// SetCacheLimits updates the cache limits for APIs and tools per API
func (ecs *EmbeddingCacheStore) SetCacheLimits(maxAPIs, maxToolsPerAPI int) {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	if maxAPIs > 0 {
		ecs.maxAPIs = maxAPIs
	}
	if maxToolsPerAPI > 0 {
		ecs.maxToolsPerAPI = maxToolsPerAPI
	}
}

// GetCacheLimits returns the current cache limits
func (ecs *EmbeddingCacheStore) GetCacheLimits() (maxAPIs, maxToolsPerAPI int) {
	ecs.mu.RLock()
	defer ecs.mu.RUnlock()
	return ecs.maxAPIs, ecs.maxToolsPerAPI
}

// findLRUAPI finds the least recently used API ID (must be called with lock held)
func (ecs *EmbeddingCacheStore) findLRUAPI() string {
	var lruAPIId string
	var oldestTime time.Time
	first := true

	for apiId, apiCache := range ecs.cache {
		if first || apiCache.LastAccessed.Before(oldestTime) {
			oldestTime = apiCache.LastAccessed
			lruAPIId = apiId
			first = false
		}
	}
	return lruAPIId
}

// findLRUTool finds the least recently used tool hash key in an API cache (must be called with lock held)
func (ecs *EmbeddingCacheStore) findLRUTool(apiCache *APICache) string {
	var lruHashKey string
	var oldestTime time.Time
	first := true

	for hashKey, entry := range apiCache.Tools {
		if first || entry.LastAccessed.Before(oldestTime) {
			oldestTime = entry.LastAccessed
			lruHashKey = hashKey
			first = false
		}
	}
	return lruHashKey
}

// evictLRUAPIIfNeeded removes the LRU API if cache is at capacity (must be called with lock held)
func (ecs *EmbeddingCacheStore) evictLRUAPIIfNeeded() {
	if len(ecs.cache) >= ecs.maxAPIs {
		lruAPIId := ecs.findLRUAPI()
		if lruAPIId != "" {
			delete(ecs.cache, lruAPIId)
		}
	}
}

// evictLRUToolIfNeeded removes the LRU tool from an API cache if at capacity (must be called with lock held)
func (ecs *EmbeddingCacheStore) evictLRUToolIfNeeded(apiCache *APICache) {
	if len(apiCache.Tools) >= ecs.maxToolsPerAPI {
		lruHashKey := ecs.findLRUTool(apiCache)
		if lruHashKey != "" {
			delete(apiCache.Tools, lruHashKey)
		}
	}
}

// HashDescription computes SHA-256 hash of the tool description
func HashDescription(description string) string {
	hash := sha256.Sum256([]byte(description))
	return hex.EncodeToString(hash[:])
}

// HasAPI checks if there is a cache entry for the given API ID
func (ecs *EmbeddingCacheStore) HasAPI(apiId string) bool {
	ecs.mu.RLock()
	defer ecs.mu.RUnlock()

	_, exists := ecs.cache[apiId]
	return exists
}

// GetAPICache returns the embedding cache for a specific API ID
// Returns nil if the API ID doesn't exist in the cache
// Updates the API's last accessed timestamp
func (ecs *EmbeddingCacheStore) GetAPICache(apiId string) APIEmbeddingCache {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	if apiCache, exists := ecs.cache[apiId]; exists {
		// Update API last accessed time
		apiCache.LastAccessed = time.Now()

		copyCache := make(APIEmbeddingCache, len(apiCache.Tools))
		for k, v := range apiCache.Tools {

			copyCache[k] = v
		}
		return copyCache
	}
	return nil
}

// AddAPICache creates a new empty cache for the given API ID
// If a cache already exists for this API ID, it does nothing
// Evicts the LRU API if cache is at capacity
func (ecs *EmbeddingCacheStore) AddAPICache(apiId string) {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	if _, exists := ecs.cache[apiId]; !exists {
		// Check if we need to evict an API before adding
		ecs.evictLRUAPIIfNeeded()

		ecs.cache[apiId] = &APICache{
			Tools:        make(map[string]*EmbeddingEntry),
			LastAccessed: time.Now(),
		}
	}
}

// GetEntry retrieves an embedding entry for a specific API and hash key
// Returns nil if not found
// Updates both API and tool last accessed timestamps
func (ecs *EmbeddingCacheStore) GetEntry(apiId, hashKey string) *EmbeddingEntry {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	if apiCache, exists := ecs.cache[apiId]; exists {
		if entry, found := apiCache.Tools[hashKey]; found {
			// Update timestamps on read
			apiCache.LastAccessed = time.Now()
			entry.LastAccessed = time.Now()
			return entry
		}
	}
	return nil
}

// GetEntryByDescription retrieves an embedding entry by API ID and tool description
// Automatically hashes the description to find the entry
// Updates both API and tool last accessed timestamps
func (ecs *EmbeddingCacheStore) GetEntryByDescription(apiId, description string) *EmbeddingEntry {
	hashKey := HashDescription(description)
	return ecs.GetEntry(apiId, hashKey)
}

// AddEntry adds or updates an embedding entry for a specific API
// If an entry with the same name exists in this API's cache, it removes the old one first
// The hashKey should be SHA-256 hash of the tool description
// Evicts LRU API if API cache is at capacity, and LRU tool if tool cache is at capacity
func (ecs *EmbeddingCacheStore) AddEntry(apiId, hashKey, name string, embedding []float32) {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	// Check if API cache exists, if not, check limits and possibly evict
	if _, exists := ecs.cache[apiId]; !exists {
		ecs.evictLRUAPIIfNeeded()
		ecs.cache[apiId] = &APICache{
			Tools:        make(map[string]*EmbeddingEntry),
			LastAccessed: time.Now(),
		}
	}

	apiCache := ecs.cache[apiId]
	// Update API last accessed time
	apiCache.LastAccessed = time.Now()

	// Check if there's an existing entry with the same name and remove it
	for key, entry := range apiCache.Tools {
		if entry.Name == name {
			delete(apiCache.Tools, key)
			break
		}
	}

	// Check if we need to evict a tool before adding (only if this is a new entry)
	if _, exists := apiCache.Tools[hashKey]; !exists {
		ecs.evictLRUToolIfNeeded(apiCache)
	}

	// Add new entry with current timestamp
	apiCache.Tools[hashKey] = &EmbeddingEntry{
		Name:         name,
		Embedding:    embedding,
		LastAccessed: time.Now(),
	}
}

// AddEntryByDescription adds or updates an embedding entry using the description to generate the hash key
func (ecs *EmbeddingCacheStore) AddEntryByDescription(apiId, description, name string, embedding []float32) {
	hashKey := HashDescription(description)
	ecs.AddEntry(apiId, hashKey, name, embedding)
}

// RemoveAPI removes all cached embeddings for a specific API
func (ecs *EmbeddingCacheStore) RemoveAPI(apiId string) {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	delete(ecs.cache, apiId)
}

// ClearAll removes all cached embeddings
func (ecs *EmbeddingCacheStore) ClearAll() {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	ecs.cache = make(map[string]*APICache)
}

// GetCacheStats returns statistics about the cache
func (ecs *EmbeddingCacheStore) GetCacheStats() (apiCount int, totalEntries int) {
	ecs.mu.RLock()
	defer ecs.mu.RUnlock()

	apiCount = len(ecs.cache)
	for _, apiCache := range ecs.cache {
		totalEntries += len(apiCache.Tools)
	}
	return
}
