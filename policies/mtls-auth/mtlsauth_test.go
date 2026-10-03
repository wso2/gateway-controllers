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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

func newTestRequestHeaderContext() *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
	}
}

func mustGetPolicy(t *testing.T) *MtlsAuthPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, nil)
	if err != nil {
		t.Fatalf("GetPolicy returned an error: %v", err)
	}
	mp, ok := p.(*MtlsAuthPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *MtlsAuthPolicy", p)
	}
	return mp
}

// TestMtlsAuthPolicy_DefaultParams_ProducesUniformUnauthorizedResponse guards
// the default failure response: a 401 with an exact JSON body and no
// WWW-Authenticate header.
func TestMtlsAuthPolicy_DefaultParams_ProducesUniformUnauthorizedResponse(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}

	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("content-type header = %q, want %q", got, "application/json")
	}
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q", string(resp.Body), wantBody)
	}
	if _, exists := resp.Headers["WWW-Authenticate"]; exists {
		t.Errorf("expected no WWW-Authenticate header, got %q", resp.Headers["WWW-Authenticate"])
	}

	if reqCtx.SharedContext.AuthContext == nil {
		t.Fatal("expected AuthContext to be recorded on failure")
	}
	if reqCtx.SharedContext.AuthContext.Authenticated {
		t.Error("expected AuthContext.Authenticated to be false")
	}
	if reqCtx.SharedContext.AuthContext.AuthType != AuthType {
		t.Errorf("AuthContext.AuthType = %q, want %q", reqCtx.SharedContext.AuthContext.AuthType, AuthType)
	}
}

// TestMtlsAuthPolicy_ErrorMessageFormat_Plain checks that "plain" returns the
// raw message as text/plain.
func TestMtlsAuthPolicy_ErrorMessageFormat_Plain(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"errorMessageFormat": "plain",
		"errorMessage":       "no certificate presented",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	if got := resp.Headers["content-type"]; got != "text/plain" {
		t.Errorf("content-type header = %q, want %q", got, "text/plain")
	}
	if string(resp.Body) != "no certificate presented" {
		t.Errorf("body = %q, want %q", string(resp.Body), "no certificate presented")
	}
}

// TestMtlsAuthPolicy_ErrorMessageFormat_Minimal checks that "minimal" returns
// the literal "Unauthorized" whatever errorMessage says.
func TestMtlsAuthPolicy_ErrorMessageFormat_Minimal(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"errorMessageFormat": "minimal",
		"errorMessage":       "this text must not appear",
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if got := resp.Headers["content-type"]; got != "application/json" {
		t.Errorf("content-type header = %q, want %q", got, "application/json")
	}
	if string(resp.Body) != "Unauthorized" {
		t.Errorf("body = %q, want %q", string(resp.Body), "Unauthorized")
	}
}

func TestMtlsAuthPolicy_OnFailureStatusCode_Honoured(t *testing.T) {
	p := mustGetPolicy(t)
	reqCtx := newTestRequestHeaderContext()

	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{
		"onFailureStatusCode": 403,
	})

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 403 {
		t.Errorf("StatusCode = %d, want 403", resp.StatusCode)
	}
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q", string(resp.Body), wantBody)
	}
}

// testEntity is a generated certificate plus the private key that created it.
type testEntity struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	der  []byte
}

func (e *testEntity) pemCert() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.der}))
}

// thumbprint returns the lowercase-hex SHA-256 of the certificate's DER, the
// canonical form evaluate computes and thumbprint narrowing is normalized to.
func (e *testEntity) thumbprint() string {
	sum := sha256.Sum256(e.der)
	return hex.EncodeToString(sum[:])
}

// certOpts configures one issuance, for a root, intermediate or leaf alike.
type certOpts struct {
	parent    *testEntity // nil => self-signed
	isCA      bool
	subject   pkix.Name // zero value => pkix.Name{CommonName: cn}
	uriSANs   []string
	dnsSANs   []string
	ekus      []x509.ExtKeyUsage
	notBefore time.Time
	notAfter  time.Time
}

func issueCert(t *testing.T, cn string, opts certOpts) *testEntity {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key for %q: %v", cn, err)
	}

	subject := opts.subject
	if subject.CommonName == "" && len(subject.Organization) == 0 {
		subject = pkix.Name{CommonName: cn}
	}

	notBefore, notAfter := opts.notBefore, opts.notAfter
	if notBefore.IsZero() && notAfter.IsZero() {
		notBefore = time.Now().Add(-1 * time.Hour)
		notAfter = time.Now().Add(10 * 365 * 24 * time.Hour)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("failed to generate serial number for %q: %v", cn, err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		BasicConstraintsValid: true,
		IsCA:                  opts.isCA,
	}
	if opts.isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
	}
	switch {
	case len(opts.ekus) > 0:
		tmpl.ExtKeyUsage = opts.ekus
	case !opts.isCA:
		// Client leaves default to clientAuth-only EKU, as real client
		// certificates do.
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	for _, u := range opts.uriSANs {
		parsed, err := url.Parse(u)
		if err != nil {
			t.Fatalf("invalid URI SAN %q for %q: %v", u, cn, err)
		}
		tmpl.URIs = append(tmpl.URIs, parsed)
	}
	tmpl.DNSNames = append(tmpl.DNSNames, opts.dnsSANs...)

	var parentCert *x509.Certificate
	var signer *ecdsa.PrivateKey
	if opts.parent == nil {
		parentCert = tmpl
		signer = key
	} else {
		parentCert = opts.parent.cert
		signer = opts.parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, key.Public(), signer)
	if err != nil {
		t.Fatalf("failed to create certificate for %q: %v", cn, err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("failed to parse generated certificate for %q: %v", cn, err)
	}
	return &testEntity{cert: cert, key: key, der: der}
}

func newRootCA(t *testing.T, cn string) *testEntity {
	t.Helper()
	return issueCert(t, cn, certOpts{isCA: true})
}

func newIntermediateCA(t *testing.T, parent *testEntity, cn string) *testEntity {
	t.Helper()
	return issueCert(t, cn, certOpts{isCA: true, parent: parent})
}

func newLeaf(t *testing.T, parent *testEntity, cn string, opts certOpts) *testEntity {
	t.Helper()
	opts.parent = parent
	return issueCert(t, cn, opts)
}

// xfccChainField builds an XFCC Chain= field with url.PathEscape, the inverse
// of the parser's url.PathUnescape.
func xfccChainField(certs ...*testEntity) string {
	var pemBlob strings.Builder
	for _, c := range certs {
		pemBlob.WriteString(c.pemCert())
	}
	return "Chain=" + url.PathEscape(pemBlob.String())
}

// authoritySpec is one pool entry as the controller publishes it, expressed
// with real certificates.
type authoritySpec struct {
	name    string
	role    string
	certs   []*testEntity
	uriSANs []string
	dnsSANs []string
}

// authorityResource renders spec as the JSON-decoded lazy resource the
// policy engine receives.
func authorityResource(spec authoritySpec) *policy.LazyResource {
	body := map[string]interface{}{
		"certificates": entitiesToPEMInterfaces(spec.certs),
		"role":         spec.role,
	}
	if len(spec.uriSANs) > 0 || len(spec.dnsSANs) > 0 {
		match := map[string]interface{}{}
		if len(spec.uriSANs) > 0 {
			match["uriSANs"] = stringsToInterfaces(spec.uriSANs)
		}
		if len(spec.dnsSANs) > 0 {
			match["dnsSANs"] = stringsToInterfaces(spec.dnsSANs)
		}
		body["match"] = match
	}
	return &policy.LazyResource{ID: spec.name, ResourceType: clientAuthorityResourceType, Resource: body}
}

// publishResources replaces the whole process-wide lazy resource store with
// resources and empties it again when the test ends.
func publishResources(t *testing.T, resources ...*policy.LazyResource) {
	t.Helper()
	store := policy.GetLazyResourceStoreInstance()
	if err := store.ReplaceAll(resources); err != nil {
		t.Fatalf("ReplaceAll: %v", err)
	}
	t.Cleanup(func() { _ = store.ReplaceAll(nil) })
}

// publishAuthorities publishes specs as the gateway's whole pool.
func publishAuthorities(t *testing.T, specs ...authoritySpec) {
	t.Helper()
	resources := make([]*policy.LazyResource, len(specs))
	for i, spec := range specs {
		resources[i] = authorityResource(spec)
	}
	publishResources(t, resources...)
}

// entrySpec is one accept-list entry: ca names the pool entry and roots are
// its certificates.
type entrySpec struct {
	ca          string
	roots       []*testEntity
	uriSANs     []string
	dnsSANs     []string
	thumbprints []string
}

// relaySpec is one relay pool entry.
type relaySpec struct {
	name    string
	roots   []*testEntity
	uriSANs []string
	dnsSANs []string
}

func stringsToInterfaces(ss []string) []interface{} {
	out := make([]interface{}, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}

func entitiesToPEMInterfaces(entities []*testEntity) []interface{} {
	out := make([]interface{}, len(entities))
	for i, e := range entities {
		out[i] = e.pemCert()
	}
	return out
}

// poolAuthorities is the pool a test describes: a client entry per distinct
// accept entry name, a relay entry per relay, and a "pool-<n>" client entry
// for every pool certificate no entry holds.
func poolAuthorities(t *testing.T, pool []*testEntity, entries []entrySpec, relays []relaySpec) []authoritySpec {
	t.Helper()
	var specs []authoritySpec
	held := map[*testEntity]bool{}
	named := map[string][]*testEntity{}
	for _, e := range entries {
		if roots, seen := named[e.ca]; seen {
			if !slices.Equal(roots, e.roots) {
				t.Fatalf("accept entries naming %q disagree about its certificates", e.ca)
			}
			continue
		}
		named[e.ca] = e.roots
		specs = append(specs, authoritySpec{name: e.ca, role: roleClient, certs: e.roots})
		for _, c := range e.roots {
			held[c] = true
		}
	}
	for _, r := range relays {
		specs = append(specs, authoritySpec{name: r.name, role: roleRelay, certs: r.roots, uriSANs: r.uriSANs, dnsSANs: r.dnsSANs})
		for _, c := range r.roots {
			held[c] = true
		}
	}
	for i, c := range pool {
		if !held[c] {
			specs = append(specs, authoritySpec{name: fmt.Sprintf("pool-%d", i), role: roleClient, certs: []*testEntity{c}})
		}
	}
	return specs
}

// buildParams builds the instance params for an explicit accept list.
func buildParams(entries []entrySpec) map[string]interface{} {
	acceptList := make([]interface{}, 0, len(entries))
	for _, e := range entries {
		obj := map[string]interface{}{"ca": e.ca}
		if len(e.uriSANs) > 0 || len(e.dnsSANs) > 0 {
			match := map[string]interface{}{}
			if len(e.uriSANs) > 0 {
				match["uriSANs"] = stringsToInterfaces(e.uriSANs)
			}
			if len(e.dnsSANs) > 0 {
				match["dnsSANs"] = stringsToInterfaces(e.dnsSANs)
			}
			obj["match"] = match
		}
		if len(e.thumbprints) > 0 {
			obj["thumbprints"] = stringsToInterfaces(e.thumbprints)
		}
		acceptList = append(acceptList, obj)
	}
	return map[string]interface{}{acceptParam: acceptList}
}

// buildParamsWithHeader is buildParams plus the client-certificate header
// system parameters in header (headerName, trustAny); a nil
// header leaves every one at its default.
func buildParamsWithHeader(entries []entrySpec, header map[string]interface{}) map[string]interface{} {
	params := buildParams(entries)
	for key, value := range header {
		params[key] = value
	}
	return params
}

// mustPolicy binds an instance with params, against whatever pool the test
// has published.
func mustPolicy(t *testing.T, params map[string]interface{}) *MtlsAuthPolicy {
	t.Helper()
	p, err := GetPolicy(policy.PolicyMetadata{}, params)
	if err != nil {
		t.Fatalf("GetPolicy returned an error: %v", err)
	}
	mp, ok := p.(*MtlsAuthPolicy)
	if !ok {
		t.Fatalf("GetPolicy returned %T, want *MtlsAuthPolicy", p)
	}
	return mp
}

// mustBuildPolicy publishes the pool described by pool and entries (see
// poolAuthorities) and binds an instance accepting entries.
func mustBuildPolicy(t *testing.T, pool []*testEntity, entries []entrySpec) *MtlsAuthPolicy {
	t.Helper()
	publishAuthorities(t, poolAuthorities(t, pool, entries, nil)...)
	return mustPolicy(t, buildParams(entries))
}

// mustBuildRelayPolicy is mustBuildPolicy with relays added to the pool and
// header as the header param.
func mustBuildRelayPolicy(t *testing.T, pool []*testEntity, entries []entrySpec, relays []relaySpec, header map[string]interface{}) *MtlsAuthPolicy {
	t.Helper()
	publishAuthorities(t, poolAuthorities(t, pool, entries, relays)...)
	return mustPolicy(t, buildParamsWithHeader(entries, header))
}

// urlEncodedPEMHeaderValue is the PEM text, percent-encoded.
func urlEncodedPEMHeaderValue(e *testEntity) string {
	return url.PathEscape(e.pemCert())
}

// pemWithSpacesHeaderValue is the PEM text with newlines replaced by spaces,
// as proxies emit it since a header cannot carry a newline.
func pemWithSpacesHeaderValue(e *testEntity) string {
	return strings.ReplaceAll(e.pemCert(), "\n", " ")
}

// bareBase64DERHeaderValue is the bare base64 of the certificate's DER bytes,
// with no PEM armor at all.
func bareBase64DERHeaderValue(e *testEntity) string {
	return base64.StdEncoding.EncodeToString(e.der)
}

func boolPtr(b bool) *bool { return &b }

func reqCtxWithTLS(tls *policy.DownstreamTLS) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
		Downstream:    &policy.DownstreamContext{TLS: tls},
	}
}

// reqCtxWithTLSAndHeader is reqCtxWithTLS plus a downstream snapshot carrying
// headerName: headerValue.
func reqCtxWithTLSAndHeader(tls *policy.DownstreamTLS, headerName, headerValue string) *policy.RequestHeaderContext {
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
		Downstream: &policy.DownstreamContext{
			TLS: tls,
			Request: &policy.DownstreamRequest{
				Headers: policy.NewHeaders(map[string][]string{headerName: {headerValue}}),
			},
		},
	}
}

// downstreamTLSFromLeaf builds the DownstreamTLS Envoy would report for a
// connection that presented leaf, with valid as Envoy's verdict.
func downstreamTLSFromLeaf(leaf *testEntity, valid bool) *policy.DownstreamTLS {
	return &policy.DownstreamTLS{
		MTLS:               true,
		PeerCertificatePEM: leaf.pemCert(),
		PeerCertValid:      boolPtr(valid),
		SHA256Thumbprint:   leaf.thumbprint(),
	}
}

// evaluateAndRespond returns both the evaluate result and the
// OnRequestHeaders action. evaluate only reads reqCtx, so calling it twice is
// safe.
func evaluateAndRespond(t *testing.T, p *MtlsAuthPolicy, reqCtx *policy.RequestHeaderContext) (evaluationResult, policy.RequestHeaderAction) {
	t.Helper()
	result := p.evaluate(reqCtx, nil)
	action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{})
	return result, action
}

// assertDenied asserts evaluate denied with wantReason and that
// OnRequestHeaders returned the one uniform 401 body, on every call site.
func assertDenied(t *testing.T, p *MtlsAuthPolicy, reqCtx *policy.RequestHeaderContext, wantReason string) {
	t.Helper()
	result, action := evaluateAndRespond(t, p, reqCtx)
	if result.authenticated {
		t.Fatalf("evaluate(): authenticated = true, want false (reason would have been %q)", wantReason)
	}
	if result.reason != wantReason {
		t.Errorf("evaluate() reason = %q, want %q", result.reason, wantReason)
	}

	resp, ok := action.(policy.ImmediateResponse)
	if !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
	}
	if resp.StatusCode != 401 {
		t.Errorf("StatusCode = %d, want 401", resp.StatusCode)
	}
	wantBody := `{"error":"Unauthorized","message":"Authentication failed"}`
	if string(resp.Body) != wantBody {
		t.Errorf("body = %q, want %q (deny body must be byte-identical regardless of reason %q)", resp.Body, wantBody, result.reason)
	}
}

// assertAuthenticated asserts evaluate authenticated at wantEntryIndex and
// that OnRequestHeaders passed the request through.
func assertAuthenticated(t *testing.T, p *MtlsAuthPolicy, reqCtx *policy.RequestHeaderContext, wantEntryIndex int) evaluationResult {
	t.Helper()
	result, action := evaluateAndRespond(t, p, reqCtx)
	if !result.authenticated {
		t.Fatalf("evaluate(): authenticated = false, reason = %q, want true", result.reason)
	}
	if result.entryIndex != wantEntryIndex {
		t.Errorf("evaluate() entryIndex = %d, want %d", result.entryIndex, wantEntryIndex)
	}
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("OnRequestHeaders returned %T, want policy.UpstreamRequestHeaderModifications (pass-through)", action)
	}
	return result
}

// TestMtlsAuthPolicy_Evaluate_EnvoyRejection_DerivesReason covers the reason
// derived from the dates of a certificate Envoy rejected.
func TestMtlsAuthPolicy_Evaluate_EnvoyRejection_DerivesReason(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	p := mustBuildPolicy(t, []*testEntity{rootA}, []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}})

	t.Run("not yet valid leaf", func(t *testing.T) {
		notYetValid := newLeaf(t, rootA, "client-not-yet-valid", certOpts{
			notBefore: time.Now().Add(1 * 365 * 24 * time.Hour),
			notAfter:  time.Now().Add(11 * 365 * 24 * time.Hour),
		})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(notYetValid, false))
		assertDenied(t, p, reqCtx, reasonNotYetValid)
	})

}

// TestMtlsAuthPolicy_Evaluate_AuthenticatesAndPopulatesAuthContext checks
// every AuthContext field on allow, and that an earlier layer's AuthContext
// is kept as Previous.
func TestMtlsAuthPolicy_Evaluate_AuthenticatesAndPopulatesAuthContext(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{uriSANs: []string{"urn:partner-a:payments"}})

	p := mustBuildPolicy(t, []*testEntity{rootA}, []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}})

	reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
	previous := &policy.AuthContext{Authenticated: true, AuthType: "jwt"} // sentinel: an earlier auth layer
	reqCtx.SharedContext.AuthContext = previous

	result := assertAuthenticated(t, p, reqCtx, 0)
	if result.subject != "urn:partner-a:payments" {
		t.Errorf("evaluate() subject = %q, want %q", result.subject, "urn:partner-a:payments")
	}

	auth := reqCtx.SharedContext.AuthContext
	if auth == nil {
		t.Fatal("expected AuthContext to be populated")
	}
	if !auth.Authenticated {
		t.Error("AuthContext.Authenticated = false, want true")
	}
	if auth.AuthType != AuthType {
		t.Errorf("AuthContext.AuthType = %q, want %q", auth.AuthType, AuthType)
	}
	if auth.Issuer != "auth-ca-a" {
		t.Errorf("AuthContext.Issuer = %q, want %q", auth.Issuer, "auth-ca-a")
	}
	if auth.CredentialID != leaf.thumbprint() {
		t.Errorf("AuthContext.CredentialID = %q, want %q", auth.CredentialID, leaf.thumbprint())
	}
	if auth.Subject != "urn:partner-a:payments" {
		t.Errorf("AuthContext.Subject = %q, want %q", auth.Subject, "urn:partner-a:payments")
	}
	if auth.Properties["source"] != "handshake" {
		t.Errorf(`AuthContext.Properties["source"] = %q, want "handshake"`, auth.Properties["source"])
	}
	if auth.Properties["matchedEntry"] != "0" {
		t.Errorf(`AuthContext.Properties["matchedEntry"] = %q, want "0"`, auth.Properties["matchedEntry"])
	}
	if auth.Previous != previous {
		t.Errorf("AuthContext.Previous = %+v, want the earlier AuthContext kept in Previous", auth.Previous)
	}
}

// TestMtlsAuthPolicy_Evaluate_IntermediateViaXFCCChain covers a missing
// intermediate, one supplied in the XFCC Chain element, the header ignored
// without MTLS, and a chain certificate never promoted to a root.
func TestMtlsAuthPolicy_Evaluate_IntermediateViaXFCCChain(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	intermediateA := newIntermediateCA(t, rootA, "Partner A Issuing CA 1")
	leaf := newLeaf(t, intermediateA, "client-via-intermediate", certOpts{})
	entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}

	t.Run("XFCC Chain carries the intermediate: authenticated", func(t *testing.T) {
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		// The client presented leaf and intermediate, so Envoy verified and
		// forwarded the intermediate in the XFCC Chain element.
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		reqCtx.Headers = policy.NewHeaders(map[string][]string{xfccHeaderName: {xfccChainField(intermediateA)}})
		assertAuthenticated(t, p, reqCtx, 0)
	})

	t.Run("same XFCC but MTLS false: still denied, header never read", func(t *testing.T) {
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		tls := downstreamTLSFromLeaf(leaf, true)
		tls.MTLS = false
		reqCtx := reqCtxWithTLS(tls)
		reqCtx.Headers = policy.NewHeaders(map[string][]string{xfccHeaderName: {xfccChainField(intermediateA)}})
		assertDenied(t, p, reqCtx, reasonNoCertificate)
	})

	t.Run("XFCC Chain ending in an unpooled self-consistent root never becomes a trusted root", func(t *testing.T) {
		rogueRoot := newRootCA(t, "Rogue Root CA")
		rogueLeaf := newLeaf(t, rogueRoot, "client-rogue", certOpts{})
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		// PeerCertValid=true isolates this policy's own chain building: a
		// self-signed CA in the XFCC chain is path-building material only, never a
		// root.
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(rogueLeaf, true))
		reqCtx.Headers = policy.NewHeaders(map[string][]string{xfccHeaderName: {xfccChainField(rogueRoot)}})
		assertDenied(t, p, reqCtx, reasonAuthorityNotAccepted)
	})
}

// TestMtlsAuthPolicy_Evaluate_SANNarrowing covers a match among several URIs,
// no match, and uriSANs with dnsSANs where only one is satisfied.
func TestMtlsAuthPolicy_Evaluate_SANNarrowing(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")

	t.Run("matches one of several leaf URIs", func(t *testing.T) {
		entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		// The first URI deliberately does not match, so the subject must come from
		// entry.uriSANs, not leaf.URIs[0].
		leaf := newLeaf(t, rootA, "client-multi-uri", certOpts{
			uriSANs: []string{"urn:partner-a:other", "urn:partner-a:payments"},
		})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.subject != "urn:partner-a:payments" {
			t.Errorf("subject = %q, want %q", result.subject, "urn:partner-a:payments")
		}
	})

	t.Run("both uriSANs and dnsSANs configured, only one satisfied", func(t *testing.T) {
		entries := []entrySpec{{
			ca:      "auth-ca-a",
			roots:   []*testEntity{rootA},
			uriSANs: []string{"urn:partner-a:payments"},
			dnsSANs: []string{"expected.partner-a.test"},
		}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		leaf := newLeaf(t, rootA, "client-partial-match", certOpts{
			uriSANs: []string{"urn:partner-a:payments"}, // satisfies the uriSANs narrowing
			dnsSANs: []string{"other.partner-a.test"},   // does NOT satisfy dnsSANs
		})
		reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
		assertDenied(t, p, reqCtx, reasonSANMismatch)
	})
}

// TestMtlsAuthPolicy_Evaluate_AuthoredAcceptForm guards that the accept list
// is read as the author wrote it: a padded ca name and a prefixed, uppercase,
// colon-separated thumbprint still match.
func TestMtlsAuthPolicy_Evaluate_AuthoredAcceptForm(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{})
	publishAuthorities(t, authoritySpec{name: "auth-ca-a", role: roleClient, certs: []*testEntity{rootA}})

	hexPrint := strings.ToUpper(leaf.thumbprint())
	var pairs []string
	for i := 0; i < len(hexPrint); i += 2 {
		pairs = append(pairs, hexPrint[i:i+2])
	}
	p := mustPolicy(t, map[string]interface{}{
		acceptParam: []interface{}{map[string]interface{}{
			"ca":          "  auth-ca-a ",
			"thumbprints": []interface{}{"SHA256:" + strings.Join(pairs, ":")},
		}},
	})

	result := assertAuthenticated(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true)), 0)
	if result.issuerCA != "auth-ca-a" {
		t.Errorf("issuerCA = %q, want the trimmed name auth-ca-a", result.issuerCA)
	}
}

// TestMtlsAuthPolicy_Evaluate_MultipleEntries_SecondMatches guards that
// matchedEntry is the index that verified, not always 0.
func TestMtlsAuthPolicy_Evaluate_MultipleEntries_SecondMatches(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	rootX := newRootCA(t, "Unrelated Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{})

	entries := []entrySpec{
		{ca: "auth-ca-x", roots: []*testEntity{rootX}}, // never matches this leaf
		{ca: "auth-ca-a", roots: []*testEntity{rootA}}, // matches
	}
	p := mustBuildPolicy(t, []*testEntity{rootA, rootX}, entries)

	reqCtx := reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true))
	result := assertAuthenticated(t, p, reqCtx, 1)
	if result.issuerCA != "auth-ca-a" {
		t.Errorf("issuerCA = %q, want %q", result.issuerCA, "auth-ca-a")
	}
	if got := reqCtx.SharedContext.AuthContext.Properties["matchedEntry"]; got != "1" {
		t.Errorf(`Properties["matchedEntry"] = %q, want "1"`, got)
	}
}

// TestMtlsAuthPolicy_Evaluate_HeaderRelay covers header mode off, a relay
// vouching for the header in every encoding, a header ignored on a non-relay
// connection, a SAN-narrowed relay declining to vouch, and trustAny.
func TestMtlsAuthPolicy_Evaluate_HeaderRelay(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	acceptLeaf := newLeaf(t, rootA, "client-valid", certOpts{uriSANs: []string{"urn:partner-a:payments"}})
	otherAcceptLeaf := newLeaf(t, rootA, "client-other", certOpts{uriSANs: []string{"urn:partner-a:other"}})

	relayCA := newRootCA(t, "Edge LB CA")
	relayLeaf := newLeaf(t, relayCA, "edge-lb", certOpts{dnsSANs: []string{"edge-lb.internal"}})

	corpCA := newRootCA(t, "Corp CA")
	// corpOtherLeaf verifies against corpCA but lacks the "lb.corp.test" SAN a
	// narrowed relay requires.
	corpOtherLeaf := newLeaf(t, corpCA, "corp-other-service", certOpts{dnsSANs: []string{"other.corp.test"}})

	acceptEntries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	pool := []*testEntity{rootA, relayCA, corpCA}
	relays := []relaySpec{{name: "relay-edge-lb", roots: []*testEntity{relayCA}}}

	t.Run("header mode off: header present but inert, connection evaluated as itself", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, nil, nil) // no relays, trustAny defaults false
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(acceptLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(otherAcceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHandshake {
			t.Errorf("source = %q, want %q", result.source, sourceHandshake)
		}
	})

	t.Run("relay connection, header carries an accepted cert URL-encoded: authenticated via the header", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHeader {
			t.Errorf("source = %q, want %q", result.source, sourceHeader)
		}
		if result.relayedBy != "relay-edge-lb" {
			t.Errorf("relayedBy = %q, want %q", result.relayedBy, "relay-edge-lb")
		}
		if result.relaySubject != relayLeaf.cert.Subject.String() {
			t.Errorf("relaySubject = %q, want the relay leaf's own subject %q", result.relaySubject, relayLeaf.cert.Subject.String())
		}
	})

	t.Run("relay connection, header carries an accepted cert as plain PEM with newlines as spaces: authenticated", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, pemWithSpacesHeaderValue(acceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHeader {
			t.Errorf("source = %q, want %q", result.source, sourceHeader)
		}
	})

	t.Run("relay connection, header carries an accepted cert as bare base64 DER: authenticated", func(t *testing.T) {
		p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, bareBase64DERHeaderValue(acceptLeaf))
		result := assertAuthenticated(t, p, reqCtx, 0)
		if result.source != sourceHeader {
			t.Errorf("source = %q, want %q", result.source, sourceHeader)
		}
	})

	t.Run("relay entry narrowed by a dnsSAN the relay leaf doesn't carry: header ignored, connection evaluated and denied", func(t *testing.T) {
		narrowedRelays := []relaySpec{{name: "relay-corp", roots: []*testEntity{corpCA}, dnsSANs: []string{"lb.corp.test"}}}
		p := mustBuildRelayPolicy(t, pool, acceptEntries, narrowedRelays, nil)
		reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(corpOtherLeaf, true), defaultHeaderName, urlEncodedPEMHeaderValue(acceptLeaf))
		// corpOtherLeaf fails the relay's SAN narrowing, so the header is ignored
		// and the connection is judged as itself against an accept list without
		// corpCA.
		assertDenied(t, p, reqCtx, reasonAuthorityNotAccepted)
	})

}

// TestMtlsAuthPolicy_OnRequestHeaders_CertificateHeaders guards that the
// backend receives at most x-forwarded-client-cert, describing the
// certificate the caller authenticated with, and never the relayed header.
func TestMtlsAuthPolicy_OnRequestHeaders_CertificateHeaders(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	acceptLeaf := newLeaf(t, rootA, "client-valid", certOpts{uriSANs: []string{"urn:partner-a:payments"}})
	relayCA := newRootCA(t, "Edge LB CA")
	relayLeaf := newLeaf(t, relayCA, "edge-lb", certOpts{})

	acceptEntries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	pool := []*testEntity{rootA, relayCA}
	relays := []relaySpec{{name: "relay-edge-lb", roots: []*testEntity{relayCA}}}
	relayed := urlEncodedPEMHeaderValue(acceptLeaf)

	for name, tc := range map[string]struct {
		header     map[string]interface{}
		forward    bool
		reqCtx     func() *policy.RequestHeaderContext
		wantSet    *testEntity // nil: x-forwarded-client-cert is left as Envoy wrote it
		wantRemove []string
	}{
		"handshake, no relayed header: nothing changes": {
			forward: true,
			reqCtx:  func() *policy.RequestHeaderContext { return reqCtxWithTLS(downstreamTLSFromLeaf(acceptLeaf, true)) },
		},
		"handshake, relayed header ignored: header removed": {
			forward: true,
			reqCtx: func() *policy.RequestHeaderContext {
				return reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(acceptLeaf, true), defaultHeaderName, relayed)
			},
			wantRemove: []string{defaultHeaderName},
		},
		"believed from a relay: XFCC describes the relayed certificate, header removed": {
			forward: true,
			reqCtx: func() *policy.RequestHeaderContext {
				return reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, relayed)
			},
			wantSet:    acceptLeaf,
			wantRemove: []string{defaultHeaderName},
		},
		"believed under trustAny: XFCC describes the header certificate, header removed": {
			header:  map[string]interface{}{trustAnyParam: true},
			forward: true,
			reqCtx: func() *policy.RequestHeaderContext {
				return reqCtxWithTLSAndHeader(&policy.DownstreamTLS{MTLS: false}, defaultHeaderName, relayed)
			},
			wantSet:    acceptLeaf,
			wantRemove: []string{defaultHeaderName},
		},
		"forwardCertificate false: both headers removed": {
			forward: false,
			reqCtx: func() *policy.RequestHeaderContext {
				return reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, relayed)
			},
			wantRemove: []string{xfccHeaderName, defaultHeaderName},
		},
	} {
		t.Run(name, func(t *testing.T) {
			p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, tc.header)
			p.forwardCertificate = tc.forward
			action := p.OnRequestHeaders(context.Background(), tc.reqCtx(), map[string]interface{}{})
			mods, ok := action.(policy.UpstreamRequestHeaderModifications)
			if !ok {
				t.Fatalf("OnRequestHeaders returned %T, want policy.UpstreamRequestHeaderModifications", action)
			}
			if !slices.Equal(mods.HeadersToRemove, tc.wantRemove) {
				t.Errorf("HeadersToRemove = %v, want %v", mods.HeadersToRemove, tc.wantRemove)
			}
			if tc.wantSet == nil {
				if len(mods.HeadersToSet) != 0 {
					t.Errorf("HeadersToSet = %v, want none", mods.HeadersToSet)
				}
				return
			}
			if len(mods.HeadersToSet) != 1 {
				t.Fatalf("HeadersToSet = %v, want only %s", mods.HeadersToSet, xfccHeaderName)
			}
			if hash, _ := xfccFieldValue(mods.HeadersToSet[xfccHeaderName], "Hash"); hash != sha256Hex(tc.wantSet.cert.Raw) {
				t.Errorf("XFCC Hash = %q, want the thumbprint of %s", hash, tc.wantSet.cert.Subject)
			}
		})
	}
}

func TestEnvoyXFCC_RoundTrips(t *testing.T) {
	root := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, root, "client-valid", certOpts{
		uriSANs: []string{"urn:partner-a:payments", "urn:partner-a:x;Hash=forged"},
		dnsSANs: []string{"client.partner-a.test", "alt.partner-a.test"},
	}).cert

	xfcc := envoyXFCC(leaf)

	if hash, _ := xfccFieldValue(xfcc, "Hash"); hash != sha256Hex(leaf.Raw) {
		t.Errorf("Hash = %q, want %q", hash, sha256Hex(leaf.Raw))
	}
	if subject, _ := xfccFieldValue(xfcc, "Subject"); subject != leaf.Subject.String() {
		t.Errorf("Subject = %q, want %q", subject, leaf.Subject.String())
	}
	encoded, ok := xfccFieldValue(xfcc, "Cert")
	if !ok {
		t.Fatalf("no Cert element in %q", xfcc)
	}
	decoded, err := url.PathUnescape(encoded)
	if err != nil {
		t.Fatalf("Cert is not percent-encoded: %v", err)
	}
	if certs := parsePEMCertificates(decoded); len(certs) != 1 || !bytes.Equal(certs[0].Raw, leaf.Raw) {
		t.Errorf("Cert does not decode to the certificate")
	}
	if _, ok := xfccFieldValue(xfcc, "Chain"); ok {
		t.Errorf("unexpected Chain element in %q", xfcc)
	}

	if got := xfccElements(t, xfcc, "URI"); !slices.Equal(got, []string{"urn:partner-a:payments", "urn:partner-a:x;Hash=forged"}) {
		t.Errorf("URI elements = %v", got)
	}
	if got := xfccElements(t, xfcc, "DNS"); !slices.Equal(got, []string{"client.partner-a.test", "alt.partner-a.test"}) {
		t.Errorf("DNS elements = %v", got)
	}
	if got := xfccElements(t, xfcc, "Hash"); len(got) != 1 {
		t.Errorf("Hash elements = %v, want exactly one — a SAN must not inject an element", got)
	}

	wantOrder := []string{"Hash", "Cert", "Subject", "URI", "URI", "DNS", "DNS"}
	if got := xfccKeys(t, xfcc); !slices.Equal(got, wantOrder) {
		t.Errorf("element order = %v, want %v", got, wantOrder)
	}
}

// xfccKeys returns the element keys of one XFCC hop, in order.
func xfccKeys(t *testing.T, xfcc string) []string {
	t.Helper()
	var keys []string
	for _, kv := range splitXFCC(t, xfcc) {
		keys = append(keys, kv[0])
	}
	return keys
}

// xfccElements returns every value of key in one XFCC hop, in order.
func xfccElements(t *testing.T, xfcc, key string) []string {
	t.Helper()
	var values []string
	for _, kv := range splitXFCC(t, xfcc) {
		if kv[0] == key {
			values = append(values, kv[1])
		}
	}
	return values
}

// splitXFCC splits one XFCC hop into key/value pairs, reading each element
// with xfccFieldValue on the remainder so quoting is handled exactly as the
// policy handles it.
func splitXFCC(t *testing.T, xfcc string) [][2]string {
	t.Helper()
	var pairs [][2]string
	rest := xfcc
	for rest != "" {
		eq := strings.IndexByte(rest, '=')
		if eq < 0 {
			t.Fatalf("malformed XFCC element in %q", rest)
		}
		key := rest[:eq]
		value, _ := xfccFieldValue(rest, key)
		pairs = append(pairs, [2]string{key, value})
		end := eq + 1
		if end < len(rest) && rest[end] == '"' {
			end++
			for end < len(rest) && rest[end] != '"' {
				if rest[end] == '\\' {
					end++
				}
				end++
			}
			end++
		} else {
			for end < len(rest) && rest[end] != ';' {
				end++
			}
		}
		rest = strings.TrimPrefix(rest[end:], ";")
	}
	return pairs
}

func TestGetPolicy_MalformedNarrowingFailsClosed(t *testing.T) {
	entries := []entrySpec{{ca: "auth-ca-a"}}

	for name, mutate := range map[string]func(entry map[string]interface{}){
		"thumbprints as a scalar": func(e map[string]interface{}) { e["thumbprints"] = "9f86d081" },
		"uriSANs as a scalar":     func(e map[string]interface{}) { e["match"] = map[string]interface{}{"uriSANs": "urn:x"} },
		"dnsSANs with a non-string": func(e map[string]interface{}) {
			e["match"] = map[string]interface{}{"dnsSANs": []interface{}{"a", 7}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			params := buildParams(entries)
			entry := params[acceptParam].([]interface{})[0].(map[string]interface{})
			mutate(entry)
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err == nil {
				t.Fatalf("expected GetPolicy to refuse a malformed narrowing, got nil error")
			}
		})
	}
}

func TestGetPolicy_EmptyNarrowingFailsClosed(t *testing.T) {
	entries := []entrySpec{{ca: "auth-ca-a"}}

	for name, tc := range map[string]struct {
		mutate  func(entry map[string]interface{})
		message string
	}{
		"empty match": {
			mutate:  func(e map[string]interface{}) { e["match"] = map[string]interface{}{} },
			message: "accept[0].match must list uriSANs or dnsSANs",
		},
		"empty uriSANs": {
			mutate:  func(e map[string]interface{}) { e["match"] = map[string]interface{}{"uriSANs": []interface{}{}} },
			message: "accept[0].match must list uriSANs or dnsSANs",
		},
		"empty uriSANs and dnsSANs": {
			mutate: func(e map[string]interface{}) {
				e["match"] = map[string]interface{}{"uriSANs": []interface{}{}, "dnsSANs": []interface{}{}}
			},
			message: "accept[0].match must list uriSANs or dnsSANs",
		},
		"empty thumbprints": {
			mutate:  func(e map[string]interface{}) { e["thumbprints"] = []interface{}{} },
			message: "accept[0].thumbprints must list at least one thumbprint",
		},
		"missing ca": {
			mutate:  func(e map[string]interface{}) { delete(e, "ca") },
			message: "accept[0].ca is required",
		},
		"blank ca": {
			mutate:  func(e map[string]interface{}) { e["ca"] = "  " },
			message: "accept[0].ca is required",
		},
		"thumbprint that is not 64 hex characters": {
			mutate:  func(e map[string]interface{}) { e["thumbprints"] = []interface{}{"sha256:9f86d081"} },
			message: "accept[0].thumbprints[0] must be a SHA-256 thumbprint of 64 hex characters",
		},
		"thumbprint with a non-hex character": {
			mutate:  func(e map[string]interface{}) { e["thumbprints"] = []interface{}{strings.Repeat("g", 64)} },
			message: "accept[0].thumbprints[0] must be a SHA-256 thumbprint of 64 hex characters",
		},
	} {
		t.Run(name, func(t *testing.T) {
			params := buildParams(entries)
			entry := params[acceptParam].([]interface{})[0].(map[string]interface{})
			tc.mutate(entry)
			_, err := GetPolicy(policy.PolicyMetadata{}, params)
			if err == nil {
				t.Fatalf("expected GetPolicy to refuse an empty narrowing, got nil error")
			}
			if !strings.Contains(err.Error(), tc.message) {
				t.Fatalf("GetPolicy error = %q, want it to contain %q", err.Error(), tc.message)
			}
		})
	}
}

// A relayed certificate is held to the same rules as one on the handshake: it
// must allow client authentication, and a certificate authority is never a
// caller, however it arrives.
func TestMtlsAuthPolicy_OnlyClientLeavesAuthenticate(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	clientLeaf := newLeaf(t, rootA, "client-valid", certOpts{})
	serverOnlyLeaf := newLeaf(t, rootA, "partner-web", certOpts{ekus: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})

	relayCA := newRootCA(t, "Edge LB CA")
	relayLeaf := newLeaf(t, relayCA, "edge-lb", certOpts{dnsSANs: []string{"edge-lb.internal"}})

	acceptEntries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}
	pool := []*testEntity{rootA, relayCA}
	relays := []relaySpec{{name: "relay-edge-lb", roots: []*testEntity{relayCA}}}
	p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
	viaRelay := func(value string) *policy.RequestHeaderContext {
		return reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, value)
	}

	t.Run("a relayed client leaf authenticates", func(t *testing.T) {
		assertAuthenticated(t, p, viaRelay(urlEncodedPEMHeaderValue(clientLeaf)), 0)
	})
	t.Run("a relayed server-only leaf is refused", func(t *testing.T) {
		assertDenied(t, p, viaRelay(urlEncodedPEMHeaderValue(serverOnlyLeaf)), reasonAuthorityNotAccepted)
	})
	t.Run("a relayed certificate authority is refused", func(t *testing.T) {
		assertDenied(t, p, viaRelay(urlEncodedPEMHeaderValue(rootA)), reasonInvalidCert)
	})
	t.Run("a relayed chain with the authority first is refused", func(t *testing.T) {
		chain := url.PathEscape(rootA.pemCert() + clientLeaf.pemCert())
		assertDenied(t, p, viaRelay(chain), reasonInvalidCert)
	})
	t.Run("a certificate authority on the handshake is refused", func(t *testing.T) {
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(rootA, true)), reasonInvalidCert)
	})
}

// A relayed chain links a caller to a pooled root through its intermediate, as
// a handshake chain does; the intermediate never authenticates by itself.
func TestMtlsAuthPolicy_RelayedChainLinksToAPooledRoot(t *testing.T) {
	root := newRootCA(t, "Partner C Root CA")
	intermediate := newIntermediateCA(t, root, "Partner C Issuing CA")
	caller := newLeaf(t, intermediate, "caller-c", certOpts{})
	otherRoot := newRootCA(t, "Other Root CA")
	otherIntermediate := newIntermediateCA(t, otherRoot, "Other Issuing CA")
	stranger := newLeaf(t, otherIntermediate, "stranger", certOpts{})

	relayCA := newRootCA(t, "Edge LB CA")
	relayLeaf := newLeaf(t, relayCA, "edge-lb", certOpts{dnsSANs: []string{"edge-lb.internal"}})

	acceptEntries := []entrySpec{{ca: "partner-c-root", roots: []*testEntity{root}}}
	pool := []*testEntity{root, relayCA}
	relays := []relaySpec{{name: "relay-edge-lb", roots: []*testEntity{relayCA}}}
	p := mustBuildRelayPolicy(t, pool, acceptEntries, relays, nil)
	viaRelay := func(value string) *policy.RequestHeaderContext {
		return reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(relayLeaf, true), defaultHeaderName, value)
	}

	t.Run("the leaf alone does not reach the pooled root", func(t *testing.T) {
		assertDenied(t, p, viaRelay(urlEncodedPEMHeaderValue(caller)), reasonUntrustedChain)
	})
	t.Run("leaf then intermediate, URL-encoded, authenticates the leaf", func(t *testing.T) {
		result := assertAuthenticated(t, p, viaRelay(url.PathEscape(caller.pemCert()+intermediate.pemCert())), 0)
		if result.subjectDN != caller.cert.Subject.String() {
			t.Errorf("subject = %q, want the caller %q", result.subjectDN, caller.cert.Subject.String())
		}
	})
	t.Run("leaf then intermediate, line breaks as spaces, authenticates the leaf", func(t *testing.T) {
		value := strings.ReplaceAll(strings.TrimSpace(caller.pemCert()+intermediate.pemCert()), "\n", " ")
		assertAuthenticated(t, p, viaRelay(value), 0)
	})
	t.Run("an intermediate from another root does not help", func(t *testing.T) {
		assertDenied(t, p, viaRelay(url.PathEscape(stranger.pemCert()+otherIntermediate.pemCert())), reasonUntrustedChain)
	})
	t.Run("an intermediate first is refused, not used as the caller", func(t *testing.T) {
		assertDenied(t, p, viaRelay(url.PathEscape(intermediate.pemCert()+caller.pemCert())), reasonInvalidCert)
	})
}

func TestParseHeaderConfig(t *testing.T) {
	for name, tc := range map[string]struct {
		params map[string]interface{}
		want   headerConfig
	}{
		"absent": {
			params: map[string]interface{}{},
			want:   headerConfig{name: defaultHeaderName},
		},
		"all set": {
			params: map[string]interface{}{headerNameParam: "X-Client-Cert", trustAnyParam: true},
			want:   headerConfig{name: "X-Client-Cert", trustAny: true},
		},
		"blank name": {
			params: map[string]interface{}{headerNameParam: "  "},
			want:   headerConfig{name: defaultHeaderName},
		},
		"wrong types": {
			params: map[string]interface{}{headerNameParam: 7, trustAnyParam: "true"},
			want:   headerConfig{name: defaultHeaderName},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := parseHeaderConfig(tc.params); got != tc.want {
				t.Errorf("parseHeaderConfig(%v) = %+v, want %+v", tc.params, got, tc.want)
			}
		})
	}
}
