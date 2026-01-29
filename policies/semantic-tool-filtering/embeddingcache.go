/*
 *  Copyright (c) 2026, WSO2 LLC. (http://www.wso2.org) All Rights Reserved.
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
	"log/slog"
	"sync"
	"time"
)

// Cache limits configuration
const (
	DefaultMaxAPIs        = 100  // Maximum number of APIs to store in cache
	DefaultMaxToolsPerAPI = 200 // Maximum number of tools per API
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
	mu             sync.RWMutex
	cache          map[string]*APICache // Key: API ID → Value: APICache
	maxAPIs        int
	maxToolsPerAPI int
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
			slog.Debug("Evicting LRU API", "apiId", lruAPIId, "currentSize", len(ecs.cache), "maxSize", ecs.maxAPIs)
			delete(ecs.cache, lruAPIId)
			slog.Debug("LRU API evicted", "evictedApiId", lruAPIId, "newSize", len(ecs.cache))
		} else {
			slog.Debug("No LRU API found to evict", "currentSize", len(ecs.cache), "maxSize", ecs.maxAPIs)
		}
	}
}

// evictLRUToolIfNeeded removes the LRU tool from an API cache if at capacity (must be called with lock held)
func (ecs *EmbeddingCacheStore) evictLRUToolIfNeeded(apiCache *APICache) {
	if len(apiCache.Tools) >= ecs.maxToolsPerAPI {
		lruHashKey := ecs.findLRUTool(apiCache)
		if lruHashKey != "" {
			toolName := ""
			if entry, exists := apiCache.Tools[lruHashKey]; exists {
				toolName = entry.Name
			}
			slog.Debug("Evicting LRU tool", "toolName", toolName, "hash", lruHashKey[:16], "currentSize", len(apiCache.Tools), "maxSize", ecs.maxToolsPerAPI)
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
		slog.Debug("Adding new API cache", "apiId", apiId, "currentCacheSize", len(ecs.cache), "maxAPIs", ecs.maxAPIs)
		// Check if we need to evict an API before adding
		ecs.evictLRUAPIIfNeeded()

		ecs.cache[apiId] = &APICache{
			Tools:        make(map[string]*EmbeddingEntry),
			LastAccessed: time.Now(),
		}
		slog.Debug("API cache added successfully", "apiId", apiId, "newCacheSize", len(ecs.cache))
	} else {
		slog.Debug("API cache already exists", "apiId", apiId)
	}
}

// GetEntry retrieves an embedding entry for a specific API and hash key
// Returns nil if not found
// Updates both API and tool last accessed timestamps
func (ecs *EmbeddingCacheStore) GetEntry(apiId, hashKey string) *EmbeddingEntry {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	slog.Debug("GetEntry called", "apiId", apiId, "hashKey", hashKey[:16], "cachedAPIs", ecs.getCachedAPIIds())

	if apiCache, exists := ecs.cache[apiId]; exists {
		if entry, found := apiCache.Tools[hashKey]; found {
			// Update timestamps on read
			apiCache.LastAccessed = time.Now()
			entry.LastAccessed = time.Now()
			slog.Debug("GetEntry cache hit", "apiId", apiId, "toolName", entry.Name)
			return entry
		}
		slog.Debug("GetEntry tool not found in API cache", "apiId", apiId)
	} else {
		slog.Debug("GetEntry API not found in cache", "apiId", apiId)
	}
	return nil
}

// AddEntry adds or updates an embedding entry for a specific API
// If an entry with the same name exists in this API's cache, it removes the old one first
// The hashKey should be SHA-256 hash of the tool description
// Evicts LRU API if API cache is at capacity, and LRU tool if tool cache is at capacity
func (ecs *EmbeddingCacheStore) AddEntry(apiId, hashKey, name string, embedding []float32) {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	slog.Debug("AddEntry called", "apiId", apiId, "toolName", name, "cachedAPIs", ecs.getCachedAPIIds())

	// Check if API cache exists, if not, check limits and possibly evict
	if _, exists := ecs.cache[apiId]; !exists {
		slog.Debug("AddEntry creating new API cache", "apiId", apiId, "currentSize", len(ecs.cache), "maxAPIs", ecs.maxAPIs)
		ecs.evictLRUAPIIfNeeded()
		ecs.cache[apiId] = &APICache{
			Tools:        make(map[string]*EmbeddingEntry),
			LastAccessed: time.Now(),
		}
		slog.Debug("AddEntry new API cache created", "apiId", apiId, "newSize", len(ecs.cache))
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
	slog.Debug("AddEntry tool added", "apiId", apiId, "toolName", name, "toolsInAPI", len(apiCache.Tools))
}

// ToolEntry represents a tool to be added to the cache
type ToolEntry struct {
	HashKey   string
	Name      string
	Embedding []float32
}

// BulkAddResult contains the result of a bulk add operation
type BulkAddResult struct {
	Added   []string // Names of tools that were added to the cache
	Skipped []string // Names of tools that were skipped due to cache limit
	Cached  []string // Names of tools that were already in cache (updated)
}

// BulkAddTools adds multiple tools to the cache for a specific API in an optimized way.
// It first checks which tools are already cached, then only adds new tools up to the cache limit.
// This prevents wasteful evictions where a tool is evicted only for the next tool to also need eviction.
//
// Logic:
// 1. Separate tools into already-cached and new tools
// 2. Update timestamps for already-cached tools
// 3. Calculate available slots for new tools
// 4. Only add new tools that fit within the limit, skip the rest
//
// Returns BulkAddResult with lists of added, skipped, and already-cached tools
func (ecs *EmbeddingCacheStore) BulkAddTools(apiId string, tools []ToolEntry) BulkAddResult {
	ecs.mu.Lock()
	defer ecs.mu.Unlock()

	result := BulkAddResult{
		Added:   make([]string, 0),
		Skipped: make([]string, 0),
		Cached:  make([]string, 0),
	}

	if len(tools) == 0 {
		return result
	}

	slog.Debug("BulkAddTools called", "apiId", apiId, "toolCount", len(tools), "maxToolsPerAPI", ecs.maxToolsPerAPI)

	// Check if API cache exists, if not, create it
	if _, exists := ecs.cache[apiId]; !exists {
		slog.Debug("BulkAddTools creating new API cache", "apiId", apiId)
		ecs.evictLRUAPIIfNeeded()
		ecs.cache[apiId] = &APICache{
			Tools:        make(map[string]*EmbeddingEntry),
			LastAccessed: time.Now(),
		}
	}

	apiCache := ecs.cache[apiId]
	apiCache.LastAccessed = time.Now()

	// Separate tools into already-cached and new tools
	var newTools []ToolEntry

	for _, tool := range tools {
		if entry, exists := apiCache.Tools[tool.HashKey]; exists {
			// Tool already exists in cache - update timestamp and embedding
			entry.LastAccessed = time.Now()
			entry.Embedding = tool.Embedding
			result.Cached = append(result.Cached, tool.Name)
			slog.Debug("BulkAddTools tool already cached", "toolName", tool.Name)
		} else {
			// Check if there's an existing entry with the same name (different hash)
			for key, entry := range apiCache.Tools {
				if entry.Name == tool.Name {
					// Remove old entry with different hash, will be re-added with new hash
					delete(apiCache.Tools, key)
					break
				}
			}
			newTools = append(newTools, tool)
		}
	}

	slog.Debug("BulkAddTools categorized tools", "cached", len(result.Cached), "new", len(newTools))

	// Calculate available slots for new tools
	availableSlots := ecs.maxToolsPerAPI - len(apiCache.Tools)
	if availableSlots < 0 {
		availableSlots = 0
	}

	slog.Debug("BulkAddTools available slots", "currentTools", len(apiCache.Tools), "maxTools", ecs.maxToolsPerAPI, "availableSlots", availableSlots)

	// Determine how many new tools we can add
	toolsToAddCount := len(newTools)
	if toolsToAddCount > availableSlots {
		// Mark tools that won't fit as skipped
		for _, tool := range newTools[availableSlots:] {
			result.Skipped = append(result.Skipped, tool.Name)
			slog.Debug("BulkAddTools skipping tool due to cache limit", "toolName", tool.Name)
		}
		toolsToAddCount = availableSlots
	}

	// Add the new tools that fit
	for i := 0; i < toolsToAddCount; i++ {
		tool := newTools[i]
		apiCache.Tools[tool.HashKey] = &EmbeddingEntry{
			Name:         tool.Name,
			Embedding:    tool.Embedding,
			LastAccessed: time.Now(),
		}
		result.Added = append(result.Added, tool.Name)
		slog.Debug("BulkAddTools added new tool", "toolName", tool.Name)
	}

	slog.Debug("BulkAddTools completed", "apiId", apiId, "added", len(result.Added), "skipped", len(result.Skipped), "cached", len(result.Cached), "totalToolsInCache", len(apiCache.Tools))

	return result
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

// getCachedAPIIds returns a list of currently cached API IDs (must be called with lock held)
func (ecs *EmbeddingCacheStore) getCachedAPIIds() []string {
	ids := make([]string, 0, len(ecs.cache))
	for id := range ecs.cache {
		ids = append(ids, id)
	}
	return ids
}
