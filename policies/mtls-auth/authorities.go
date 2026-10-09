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
package mtlsauth

import (
	"crypto/x509"
	"fmt"
	"log/slog"
	"sort"
	"sync"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// clientAuthorityResourceType is the lazy resource type the controller
// publishes each client-CA pool entry under, keyed by entry name, with a body
// of {"certificates": [PEM...], "role": "client" | "relay", "match":
// {"uriSANs", "dnsSANs"}}. Only a narrowed relay entry carries "match".
const clientAuthorityResourceType = "ClientCertificateAuthority"

// The two roles a pool entry can have. A client entry can be named by an
// accept list; a relay entry never can, and exists only so this policy can
// recognise a front proxy's connection.
const (
	roleClient = "client"
	roleRelay  = "relay"
)

// relayEntry is one parsed relay entry of the pool. The policy uses it only
// to decide whether the CONNECTION's own certificate came from a trusted
// relay, never to authenticate the relay as an API caller.
type relayEntry struct {
	name  string
	roots *x509.CertPool

	// nil uriSANs/dnsSANs mean no SAN narrowing, as for acceptEntry.
	uriSANs []string
	dnsSANs []string
}

// authoritySet is the pool as parsed from one version of the lazy resource
// store. It is immutable once built: every request reading it sees the same
// complete set until a newer one replaces it.
type authoritySet struct {
	version uint64

	clients map[string]*x509.CertPool

	// inherited is the accept list of an instance whose author omitted
	// accept: every client entry, in name order, with no narrowing.
	inherited []acceptEntry

	relays []relayEntry

	// pool holds every certificate of every entry (relays included). It is
	// path-building material, and the root set only for choosing a deny
	// reason (chainsToPool) — never for allowing a request.
	pool *x509.CertPool

	// warned records the log keys already written for this set, so a warning
	// about the pool is logged once per store version, not once per request.
	warned sync.Map
}

// firstWarning reports whether key has not yet been logged for this set,
// recording it as logged.
func (s *authoritySet) firstWarning(key string) bool {
	_, logged := s.warned.LoadOrStore(key, struct{}{})
	return !logged
}

// buildAuthoritySet parses resources (every ClientCertificateAuthority
// resource in the store, keyed by entry name) into a set tagged with
// version. An entry that cannot be read is skipped and logged; the rest of
// the pool is unaffected, and requests naming the skipped entry deny as
// though it were absent.
func buildAuthoritySet(resources map[string]*policy.LazyResource, version uint64) *authoritySet {
	set := &authoritySet{
		version: version,
		clients: make(map[string]*x509.CertPool),
		pool:    x509.NewCertPool(),
	}

	names := make([]string, 0, len(resources))
	for name := range resources {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		entry, err := parseAuthorityResource(resources[name])
		if err != nil {
			slog.Warn("mtls-auth: skipping a client certificate authority that could not be read",
				slog.String("ca", name),
				slog.String("error", err.Error()),
			)
			continue
		}
		roots := x509.NewCertPool()
		for _, cert := range entry.certificates {
			roots.AddCert(cert)
			set.pool.AddCert(cert)
		}
		switch entry.role {
		case roleClient:
			set.clients[name] = roots
			set.inherited = append(set.inherited, acceptEntry{ca: name})
		case roleRelay:
			set.relays = append(set.relays, relayEntry{name: name, roots: roots, uriSANs: entry.uriSANs, dnsSANs: entry.dnsSANs})
		}
	}
	return set
}

// parsedAuthority is one successfully read ClientCertificateAuthority
// resource.
type parsedAuthority struct {
	role         string
	certificates []*x509.Certificate
	uriSANs      []string
	dnsSANs      []string
}

// parseAuthorityResource reads one ClientCertificateAuthority resource. Any
// malformed field — no certificates, a certificate that does not parse, an
// unknown role, a malformed match — makes the whole entry unreadable rather
// than partially used: a half-read entry could widen what a relay's match
// admits.
func parseAuthorityResource(resource *policy.LazyResource) (parsedAuthority, error) {
	var entry parsedAuthority
	if resource == nil || resource.Resource == nil {
		return entry, fmt.Errorf("resource has no content")
	}
	body := resource.Resource

	entry.role, _ = body["role"].(string)
	if entry.role != roleClient && entry.role != roleRelay {
		return entry, fmt.Errorf("role must be %q or %q", roleClient, roleRelay)
	}

	pems, err := stringListParam(body, "certificates", "resource")
	if err != nil {
		return entry, err
	}
	if len(pems) == 0 {
		return entry, fmt.Errorf("resource.certificates must list at least one certificate")
	}
	for i, pemStr := range pems {
		cert, err := parseCertificatePEM(pemStr)
		if err != nil {
			return entry, fmt.Errorf("resource.certificates[%d]: %w", i, err)
		}
		entry.certificates = append(entry.certificates, cert)
	}

	if entry.role == roleRelay {
		if matchRaw, ok := body["match"]; ok && matchRaw != nil {
			matchObj, ok := matchRaw.(map[string]interface{})
			if !ok {
				return entry, fmt.Errorf("resource.match must be an object")
			}
			if entry.uriSANs, err = stringListParam(matchObj, "uriSANs", "resource.match"); err != nil {
				return entry, err
			}
			if entry.dnsSANs, err = stringListParam(matchObj, "dnsSANs", "resource.match"); err != nil {
				return entry, err
			}
		}
	}
	return entry, nil
}

// authorityCache holds the set built from the newest store version seen and
// rebuilds it once per version. One goroutine rebuilds at a time and
// rechecks the version under rebuildMu. Other readers keep using the previous
// complete set meanwhile, and only a reader with no set at all waits.
type authorityCache struct {
	store *policy.LazyResourceStore
	build func(resources map[string]*policy.LazyResource, version uint64) *authoritySet

	mu      sync.RWMutex
	current *authoritySet

	rebuildMu sync.Mutex
}

func newAuthorityCache(store *policy.LazyResourceStore, build func(map[string]*policy.LazyResource, uint64) *authoritySet) *authorityCache {
	return &authorityCache{store: store, build: build}
}

// clientAuthorities is the pool every instance of this policy reads: the
// process-wide lazy resource store the policy engine fills from the
// controller's snapshots.
var clientAuthorities = newAuthorityCache(policy.GetLazyResourceStoreInstance(), buildAuthoritySet)

// get returns the set for the store's current version, rebuilding it if the
// store has changed since the last build (see authorityCache).
func (c *authorityCache) get() *authoritySet {
	set := c.load()
	if set != nil && set.version == c.store.Version() {
		return set
	}

	if set == nil {
		c.rebuildMu.Lock()
	} else if !c.rebuildMu.TryLock() {
		// Another goroutine is rebuilding: the previous set is complete and
		// stays valid until the new one is published.
		return set
	}
	defer c.rebuildMu.Unlock()

	// Read the version before the resources: if the store changes while the
	// set is built, the set carries the older version and the next request
	// rebuilds it again, so a set is never tagged newer than its contents.
	version := c.store.Version()
	if set = c.load(); set != nil && set.version == version {
		return set
	}
	resources, _ := c.store.GetResourcesByType(clientAuthorityResourceType)
	built := c.build(resources, version)

	c.mu.Lock()
	c.current = built
	c.mu.Unlock()
	return built
}

func (c *authorityCache) load() *authoritySet {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.current
}
