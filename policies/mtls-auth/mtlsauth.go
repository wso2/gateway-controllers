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

// Package mtlsauth implements the mtls-auth policy. It authenticates API
// callers by matching the client certificate presented on the gateway's HTTPS
// listener against the instance's accept list: a subset of the gateway's
// client-CA pool, optionally narrowed by SAN or certificate thumbprint. The
// listener requests a client certificate but never rejects a connection over
// it, so this policy is what turns a presented certificate into an
// authenticated caller. Pool certificates are only ever path-building
// intermediates; a certificate acts as a root for a request only through the
// accept entry that names its pool entry. A front proxy may instead relay the
// client certificate in a header when the pool holds a relay entry or trustAny
// is set, but the connection's own certificate is always judged first.
package mtlsauth

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

const (
	// AuthType identifies this authentication mechanism in policy.AuthContext.
	AuthType = "mtls"

	defaultOnFailureStatusCode = 401
	defaultErrorMessageFormat  = "json"
	defaultErrorMessage        = "Authentication failed"

	// acceptParam is the author's ordered accept list of {"ca", "match":
	// {"uriSANs", "dnsSANs"}, "thumbprints"}; absent means every client entry
	// in the pool, unnarrowed.
	acceptParam = "accept"

	// System parameters resolved from the gateway's
	// router.downstream_tls.client_certificate_header configuration.
	headerNameParam = "headerName"
	trustAnyParam   = "trustAny"

	defaultHeaderName = "X-WSO2-CLIENT-CERTIFICATE"

	forwardCertificateParam = "forwardCertificate"

	// Envoy writes this header with SANITIZE_SET whenever the connection
	// presented a certificate, so a client cannot forge it.
	xfccHeaderName = "x-forwarded-client-cert"

	// Deny reasons feed logs and span attributes only. Every deny returns the
	// same configured failure response, so the caller never learns the reason.
	reasonAttributeAbsent = "attribute_absent"
	reasonNoCertificate   = "no_certificate"
	reasonExpired         = "expired"
	reasonNotYetValid     = "not_yet_valid"
	reasonUntrustedChain  = "untrusted_chain"
	reasonInvalidCert     = "invalid_certificate"

	// Accept-list rejection reasons, least to most specific. A deny reports the
	// most specific one reached across all entries.
	reasonAuthorityNotAccepted = "authority_not_accepted"
	reasonSANMismatch          = "san_mismatch"
	reasonThumbprintMismatch   = "thumbprint_mismatch"

	// Where the evaluated certificate came from: the TLS handshake, a header
	// relayed by a trusted proxy, or a header believed under trustAny.
	sourceHandshake = "handshake"
	sourceHeader    = "header"
	sourceBypass    = "bypass"
)

// acceptEntry is one parsed accept-list entry: the pool entry it names and
// the narrowing it applies.
type acceptEntry struct {
	ca string

	// nil means no SAN narrowing.
	uriSANs []string
	dnsSANs []string

	// thumbprints hold lowercase hex with no separators; nil means no
	// thumbprint narrowing.
	thumbprints []string
}

// headerConfig holds the gateway's client-certificate header settings.
type headerConfig struct {
	name     string
	trustAny bool
}

// evaluationResult is evaluate's outcome, kept small so tests can assert on
// it directly.
type evaluationResult struct {
	authenticated bool
	reason        string
	entryIndex    int // index into accept of the matched entry; -1 when authenticated is false

	// subject and issuerCA are set only on allow.
	subject  string
	issuerCA string

	// The leaf fields below are set whenever a leaf parsed and passed the date
	// check, on deny as well as allow, so spans can describe a rejected
	// certificate.
	credentialID string
	subjectDN    string
	issuerDN     string
	serialNumber string
	notAfter     time.Time

	// relayedBy and relaySubject are set whenever source is sourceHeader, on
	// deny as well as allow.
	source       string
	relayedBy    string
	relaySubject string

	// headerCertificate is the certificate the header carried, set on allow
	// when source is sourceHeader or sourceBypass.
	headerCertificate *x509.Certificate
}

// MtlsAuthPolicy authenticates API callers via mutual TLS. It holds no
// certificate material; every request reads the shared parsed pool.
type MtlsAuthPolicy struct {
	// accept is nil with inheritAccept set when the author omitted it, meaning
	// every client entry in the pool.
	accept        []acceptEntry
	inheritAccept bool

	// acceptNames is accept's pool entry names joined in order, identifying
	// this list in the warning logged when none of them is in the pool.
	acceptNames string

	header headerConfig

	// forwardCertificate false removes X-Forwarded-Client-Cert and the relayed
	// certificate header from every request this policy allows.
	forwardCertificate bool
}

// GetPolicy is the v1alpha2 factory entry point. A malformed accept list or
// forwardCertificate value refuses to bind the instance rather than guessing.
func GetPolicy(metadata policy.PolicyMetadata, params map[string]interface{}) (policy.Policy, error) {
	accept, err := parseAcceptParam(params[acceptParam])
	if err != nil {
		return nil, fmt.Errorf("mtls-auth: parsing accept list: %w", err)
	}
	forwardCertificate, err := parseForwardCertificateParam(params[forwardCertificateParam])
	if err != nil {
		return nil, fmt.Errorf("mtls-auth: %w", err)
	}
	names := make([]string, len(accept))
	for i, entry := range accept {
		names[i] = entry.ca
	}
	return &MtlsAuthPolicy{
		accept:             accept,
		inheritAccept:      params[acceptParam] == nil,
		acceptNames:        strings.Join(names, ","),
		header:             parseHeaderConfig(params),
		forwardCertificate: forwardCertificate,
	}, nil
}

// headerModeOn reports whether a client-certificate header can ever be
// believed: the pool holds at least one relay entry, or the (explicitly
// off-by-default) trustAny bypass is configured.
func (p *MtlsAuthPolicy) headerModeOn(set *authoritySet) bool {
	return len(set.relays) > 0 || p.header.trustAny
}

// acceptEntries returns the accept list evaluated against set: the author's
// own list, or — when the author omitted it — every client entry in set.
func (p *MtlsAuthPolicy) acceptEntries(set *authoritySet) []acceptEntry {
	if p.inheritAccept {
		return set.inherited
	}
	return p.accept
}

// Mode declares that mtls-auth only needs the request-header phase: the
// certificate it authenticates against is a connection-level fact (available
// as soon as headers are), never something carried in the request body.
func (p *MtlsAuthPolicy) Mode() policy.ProcessingMode {
	return policy.ProcessingMode{
		RequestHeaderMode:  policy.HeaderModeProcess,
		RequestBodyMode:    policy.BodyModeSkip,
		ResponseHeaderMode: policy.HeaderModeSkip,
		ResponseBodyMode:   policy.BodyModeSkip,
	}
}

// evaluate authenticates the request and fails closed: any step that cannot
// decide denies. The connection's own certificate is judged first. If Envoy
// verified it and it passes accept, the request is allowed and any header is
// ignored. Otherwise a single header certificate is judged, only under
// trustAny or when the connection matches a relay entry, and only for a
// connection certificate that is valid in itself but not one this API
// accepts. A connection certificate that Envoy rejected, or that is expired,
// not yet valid or unparseable, denies outright, even under trustAny, so a
// caller with a bad certificate gets no second chance. The whole request is
// judged against one version of the pool.
func (p *MtlsAuthPolicy) evaluate(reqCtx *policy.RequestHeaderContext, _ map[string]interface{}) evaluationResult {
	now := time.Now()
	set := clientAuthorities.get()
	tls := reqCtx.PeerCertificate()
	headerValues := p.headerValues(reqCtx, set)
	headerPresent := len(headerValues) > 0

	if connectionVerified(tls) {
		connectionResult := p.evaluateVerifiedConnection(set, reqCtx, tls, now)
		if connectionResult.authenticated || !headerPresent || certificateUnusable(connectionResult.reason) {
			return connectionResult
		}
		if p.header.trustAny {
			return p.evaluateHeaderCertificate(set, headerValues, now, sourceBypass, "", "")
		}
		if relay, relayLeaf, ok := set.matchRelay(reqCtx, tls, now); ok {
			return p.evaluateHeaderCertificate(set, headerValues, now, sourceHeader, relay.name, relayLeaf.Subject.String())
		}
		p.logIgnoredHeader(tls)
		return connectionResult
	}

	deny := evaluationResult{authenticated: false, entryIndex: -1, source: sourceHandshake}
	switch {
	case tls == nil:
		// Missing TLS attributes are a failure, never "no certificate required".
		deny.reason = reasonAttributeAbsent
	case !tls.MTLS:
		if headerPresent && p.header.trustAny {
			return p.evaluateHeaderCertificate(set, headerValues, now, sourceBypass, "", "")
		}
		if headerPresent {
			p.logIgnoredHeader(tls)
		}
		deny.reason = reasonNoCertificate
	case tls.PeerCertValid == nil:
		deny.reason = reasonAttributeAbsent
	default:
		reason, rejectedLeaf := set.deriveRejectReason(tls, now)
		deny.reason = reason
		if rejectedLeaf != nil {
			deny = withLeafInfo(deny, rejectedLeaf)
		}
	}
	return deny
}

// certificateUnusable reports whether reason says the connection certificate
// is bad in itself rather than merely not accepted by this API.
func certificateUnusable(reason string) bool {
	switch reason {
	case reasonExpired, reasonNotYetValid, reasonInvalidCert:
		return true
	}
	return false
}

// connectionVerified reports whether Envoy delivered a positive verdict for a
// certificate presented on this connection: TLS attributes present, a
// certificate presented, and peer_certificate_valid true.
func connectionVerified(tls *policy.DownstreamTLS) bool {
	return tls != nil && tls.MTLS && tls.PeerCertValid != nil && *tls.PeerCertValid
}

// withLeafInfo attaches non-sensitive leaf attributes to a result, a deny
// included, so spans can describe a rejected certificate.
func withLeafInfo(result evaluationResult, leaf *x509.Certificate) evaluationResult {
	result.subjectDN = leaf.Subject.String()
	result.credentialID = sha256Hex(leaf.Raw)
	result.notAfter = leaf.NotAfter
	return result
}

// evaluateVerifiedConnection evaluates a certificate Envoy already verified
// against the accept list, re-checking its validity dates first.
func (p *MtlsAuthPolicy) evaluateVerifiedConnection(set *authoritySet, reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS, now time.Time) evaluationResult {
	deny := evaluationResult{authenticated: false, entryIndex: -1, source: sourceHandshake}

	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		deny.reason = reasonInvalidCert
		return deny
	}
	if now.After(leaf.NotAfter) {
		deny.reason = reasonExpired
		return withLeafInfo(deny, leaf)
	}
	if now.Before(leaf.NotBefore) {
		deny.reason = reasonNotYetValid
		return withLeafInfo(deny, leaf)
	}

	result := p.evaluateAcceptList(set, leaf, set.connectionIntermediates(reqCtx, tls), now, tls.SHA256Thumbprint)
	result.source = sourceHandshake
	return result
}

// evaluateHeaderCertificate evaluates one header-carried certificate like a
// connection certificate, but with only pool material as intermediates and no
// Envoy thumbprint cross-check, since no handshake produced it. The relay
// fields are kept on every outcome.
func (p *MtlsAuthPolicy) evaluateHeaderCertificate(set *authoritySet, values []string, now time.Time, source, relayName, relaySubject string) evaluationResult {
	deny := evaluationResult{
		authenticated: false, entryIndex: -1,
		source: source, relayedBy: relayName, relaySubject: relaySubject,
	}

	// Several values for the header is never one identity: deny rather than
	// pick one.
	if len(values) != 1 {
		deny.reason = reasonInvalidCert
		return deny
	}
	leaf, err := decodeHeaderCertificate(values[0])
	if err != nil {
		deny.reason = reasonInvalidCert
		return deny
	}
	if now.After(leaf.NotAfter) {
		deny.reason = reasonExpired
		return withLeafInfo(deny, leaf)
	}
	if now.Before(leaf.NotBefore) {
		deny.reason = reasonNotYetValid
		return withLeafInfo(deny, leaf)
	}

	// Certificates after the caller's own in the value may only link it to a
	// pooled authority, as the intermediates of a handshake do.
	intermediates := set.headerIntermediates(values[0])
	result := p.evaluateAcceptList(set, leaf, intermediates, now, "")
	// No handshake verified this certificate, so the policy distinguishes the
	// two ways it can reach no accept entry: it chains to no pooled authority
	// at all (untrusted_chain), or it does but this API does not accept that
	// authority (authority_not_accepted).
	if result.reason == reasonAuthorityNotAccepted && !verifyLeafAgainstRoots(leaf, set.pool, intermediates, now) {
		result.reason = reasonUntrustedChain
	}
	result.source = source
	result.relayedBy = relayName
	result.relaySubject = relaySubject
	if result.authenticated {
		result.headerCertificate = leaf
	}
	return result
}

// acceptRejectRank orders the accept-list rejection reasons by specificity;
// any other reason ranks lowest.
func acceptRejectRank(reason string) int {
	switch reason {
	case reasonThumbprintMismatch:
		return 3
	case reasonSANMismatch:
		return 2
	case reasonAuthorityNotAccepted:
		return 1
	default:
		return 0
	}
}

// evaluateAcceptList allows on the first entry whose pool entry verifies leaf
// and whose narrowing leaf satisfies. A deny reports the most specific
// rejection reached across all entries. connectionThumbprint is Envoy's
// digest of the same certificate, cross-checked against thumbprint narrowing;
// it is empty for a header certificate.
func (p *MtlsAuthPolicy) evaluateAcceptList(set *authoritySet, leaf *x509.Certificate, intermediates *x509.CertPool, now time.Time, connectionThumbprint string) evaluationResult {
	canonicalThumbprint := sha256Hex(leaf.Raw)
	deny := evaluationResult{
		authenticated: false, entryIndex: -1,
		reason:       reasonAuthorityNotAccepted,
		subjectDN:    leaf.Subject.String(),
		credentialID: canonicalThumbprint,
		notAfter:     leaf.NotAfter,
	}

	upgrade := func(reason string) {
		if acceptRejectRank(reason) > acceptRejectRank(deny.reason) {
			deny.reason = reason
		}
	}

	// A certificate authority issues callers' certificates; it is never a caller.
	if leaf.IsCA {
		deny.reason = reasonInvalidCert
		return deny
	}

	inPool := 0
	for i, entry := range p.acceptEntries(set) {
		roots, ok := set.clients[entry.ca]
		if !ok {
			continue
		}
		inPool++
		if !verifyClientLeafAgainstRoots(leaf, roots, intermediates, now) {
			continue
		}

		subject, ok := sanNarrowedSubject(leaf, entry.uriSANs, entry.dnsSANs)
		if !ok {
			upgrade(reasonSANMismatch)
			continue
		}

		if len(entry.thumbprints) > 0 {
			if !containsConstantTime(entry.thumbprints, canonicalThumbprint) {
				upgrade(reasonThumbprintMismatch)
				continue
			}
			// Defense in depth: our PEM-derived digest must match Envoy's.
			if connectionThumbprint != "" && normalizeThumbprint(connectionThumbprint) != canonicalThumbprint {
				upgrade(reasonThumbprintMismatch)
				continue
			}
		}

		return evaluationResult{
			authenticated: true,
			entryIndex:    i,
			subject:       subject,
			issuerCA:      entry.ca,
			credentialID:  canonicalThumbprint,
			subjectDN:     leaf.Subject.String(),
			issuerDN:      leaf.Issuer.String(),
			serialNumber:  leaf.SerialNumber.String(),
			notAfter:      leaf.NotAfter,
		}
	}

	if inPool == 0 {
		p.warnNoAcceptedAuthority(set)
	}
	return deny
}

// warnNoAcceptedAuthority logs, once per pool version, that none of the pool
// entries this accept list names is in the pool. Every request is denied
// until one of them returns.
func (p *MtlsAuthPolicy) warnNoAcceptedAuthority(set *authoritySet) {
	key := "accept:" + p.acceptNames
	if p.inheritAccept {
		key = "inherit"
	}
	if !set.firstWarning(key) {
		return
	}
	slog.Warn("mtls-auth: none of the client certificate authorities this API accepts is in the gateway's client-CA pool",
		slog.String("accept", p.acceptNames),
		slog.Bool("inherited", p.inheritAccept),
		slog.Uint64("pool_version", set.version),
	)
}

// matchRelay reports whether the connection's own certificate, never the
// header's, authenticates as a relay entry, verified exactly like an accept
// entry.
func (s *authoritySet) matchRelay(reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS, now time.Time) (*relayEntry, *x509.Certificate, bool) {
	if !connectionVerified(tls) {
		return nil, nil, false
	}
	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		return nil, nil, false
	}
	if now.After(leaf.NotAfter) || now.Before(leaf.NotBefore) {
		return nil, nil, false
	}

	intermediates := s.connectionIntermediates(reqCtx, tls)
	for i := range s.relays {
		entry := &s.relays[i]
		if !verifyClientLeafAgainstRoots(leaf, entry.roots, intermediates, now) {
			continue
		}
		if _, ok := sanNarrowedSubject(leaf, entry.uriSANs, entry.dnsSANs); !ok {
			continue
		}
		return entry, leaf, true
	}
	return nil, nil, false
}

// logIgnoredHeader logs at Debug that a header was present but not judged.
// Only the connection's subject DN is logged, never header contents.
func (p *MtlsAuthPolicy) logIgnoredHeader(tls *policy.DownstreamTLS) {
	subject := "none"
	if tls != nil && tls.MTLS && tls.PeerCertificatePEM != "" {
		if leaf, err := parseCertificatePEM(tls.PeerCertificatePEM); err == nil {
			subject = leaf.Subject.String()
		}
	}
	slog.Debug("mtls-auth: client certificate header present on a non-relay connection",
		slog.String("subject", subject),
	)
}

// headerValues returns the non-empty values of the certificate header, or nil
// when header mode is off. It reads the downstream snapshot, so an earlier
// policy cannot change the header this decision sees.
func (p *MtlsAuthPolicy) headerValues(reqCtx *policy.RequestHeaderContext, set *authoritySet) []string {
	if !p.headerModeOn(set) {
		return nil
	}
	var values []string
	for _, v := range reqCtx.DownstreamRequest().Headers.Get(p.header.name) {
		if v = strings.TrimSpace(v); v != "" {
			values = append(values, v)
		}
	}
	return values
}

// connectionIntermediates returns path-building material for a connection
// leaf: the pool plus any XFCC Chain certificates. The shared pool is cloned,
// never modified.
func (s *authoritySet) connectionIntermediates(reqCtx *policy.RequestHeaderContext, tls *policy.DownstreamTLS) *x509.CertPool {
	if tls == nil || !tls.MTLS {
		return s.pool
	}
	chain := chainCertificatesFromXFCC(reqCtx)
	if len(chain) == 0 {
		return s.pool
	}
	intermediates := s.pool.Clone()
	for _, c := range chain {
		intermediates.AddCert(c)
	}
	return intermediates
}

// headerIntermediates is the pool plus every certificate after the first in a
// header value that carries a PEM chain. A value holding one certificate, or
// DER, adds nothing.
func (s *authoritySet) headerIntermediates(raw string) *x509.CertPool {
	chain := headerPEMChain(raw)
	if len(chain) < 2 {
		return s.pool
	}
	intermediates := s.pool.Clone()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	return intermediates
}

// headerPEMChain returns every certificate in a header value carrying PEM, in
// any form decodeHeaderCertificate accepts, or nil when it carries none.
func headerPEMChain(raw string) []*x509.Certificate {
	raw = strings.TrimSpace(raw)
	candidate := raw
	if decoded, err := url.PathUnescape(raw); err == nil {
		candidate = decoded
	}
	for _, text := range []string{raw, candidate} {
		if certs := parsePEMCertificates(text); len(certs) > 0 {
			return certs
		}
	}
	if rebuilt := reconstitutePEMArmor(candidate); rebuilt != "" {
		return parsePEMCertificates(rebuilt)
	}
	return nil
}

// verifyLeafAgainstRoots is the one x509 verification every check in this
// package uses.
func verifyLeafAgainstRoots(leaf *x509.Certificate, roots, intermediates *x509.CertPool, now time.Time) bool {
	return verifyLeaf(leaf, roots, intermediates, now, x509.ExtKeyUsageAny)
}

// verifyClientLeafAgainstRoots is verifyLeafAgainstRoots for a certificate
// that authenticates a caller or a relay: its chain must allow client
// authentication, as the TLS handshake requires. A certificate with no
// extended key usage allows any use.
func verifyClientLeafAgainstRoots(leaf *x509.Certificate, roots, intermediates *x509.CertPool, now time.Time) bool {
	return verifyLeaf(leaf, roots, intermediates, now, x509.ExtKeyUsageClientAuth)
}

func verifyLeaf(leaf *x509.Certificate, roots, intermediates *x509.CertPool, now time.Time, usage x509.ExtKeyUsage) bool {
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{usage},
		CurrentTime:   now,
	})
	return err == nil
}

// sanNarrowedSubject reports whether leaf satisfies the SAN narrowing, nil
// meaning none, and returns the subject to authenticate it as.
func sanNarrowedSubject(leaf *x509.Certificate, uriSANs, dnsSANs []string) (string, bool) {
	switch {
	case len(uriSANs) > 0:
		matched := firstMatchingSAN(uriSANStrings(leaf), uriSANs)
		if matched == "" {
			return "", false
		}
		if len(dnsSANs) > 0 && firstMatchingSAN(leaf.DNSNames, dnsSANs) == "" {
			return "", false
		}
		return matched, true
	case len(dnsSANs) > 0:
		matched := firstMatchingSAN(leaf.DNSNames, dnsSANs)
		if matched == "" {
			return "", false
		}
		return matched, true
	default:
		subject := firstOf(uriSANStrings(leaf))
		if subject == "" {
			subject = firstOf(leaf.DNSNames)
		}
		if subject == "" {
			subject = leaf.Subject.String()
		}
		return subject, true
	}
}

// deriveRejectReason picks a telemetry reason for a certificate Envoy
// rejected, and returns the leaf when it parsed so spans can still describe
// it.
func (s *authoritySet) deriveRejectReason(tls *policy.DownstreamTLS, now time.Time) (string, *x509.Certificate) {
	leaf, err := parseCertificatePEM(tls.PeerCertificatePEM)
	if err != nil {
		return reasonInvalidCert, nil
	}
	if now.After(leaf.NotAfter) {
		return reasonExpired, leaf
	}
	if now.Before(leaf.NotBefore) {
		return reasonNotYetValid, leaf
	}

	// Not a date problem — distinguish "the chain genuinely doesn't reach a
	// trusted authority" from some other reason Envoy rejected it.
	if !s.chainsToPool(leaf, now) {
		return reasonUntrustedChain, leaf
	}
	return reasonInvalidCert, leaf
}

// chainsToPool reports whether leaf verifies against any certificate in the
// whole client-CA pool. It only chooses a deny reason, never allows.
func (s *authoritySet) chainsToPool(leaf *x509.Certificate, now time.Time) bool {
	return verifyLeafAgainstRoots(leaf, s.pool, s.pool, now)
}

// chainCertificatesFromXFCC returns the XFCC Chain certificates from the
// downstream snapshot. Envoy writes the header with SANITIZE_SET, so a client
// cannot inject one.
func chainCertificatesFromXFCC(reqCtx *policy.RequestHeaderContext) []*x509.Certificate {
	values := reqCtx.DownstreamRequest().Headers.Get(xfccHeaderName)
	if len(values) == 0 {
		return nil
	}
	return parseXFCCChainCertificates(values[0])
}

// OnRequestHeaders performs mTLS authentication in the request-header phase.
func (p *MtlsAuthPolicy) OnRequestHeaders(ctx context.Context, reqCtx *policy.RequestHeaderContext, params map[string]interface{}) policy.RequestHeaderAction {
	onFailureStatusCode := getIntParam(params, "onFailureStatusCode", defaultOnFailureStatusCode)
	errorMessageFormat := getStringParam(params, "errorMessageFormat", defaultErrorMessageFormat)
	errorMessage := getStringParam(params, "errorMessage", defaultErrorMessage)

	result := p.evaluate(reqCtx, params)
	setSpanAttributes(ctx, result, reqCtx.PeerCertificate())

	if !result.authenticated {
		slog.Debug("mtls-auth: rejecting request",
			slog.String("reason", result.reason),
			slog.String("subject", result.subjectDN),
			slog.String("source", result.source),
			slog.String("api", reqCtx.APIName),
			slog.String("path", reqCtx.Path),
		)
		return p.handleAuthFailure(reqCtx.SharedContext, onFailureStatusCode, errorMessageFormat, errorMessage)
	}

	properties := map[string]string{
		"subjectDN":    result.subjectDN,
		"issuerDN":     result.issuerDN,
		"serialNumber": result.serialNumber,
		"notAfter":     result.notAfter.UTC().Format(time.RFC3339),
		"matchedEntry": strconv.Itoa(result.entryIndex),
		"source":       result.source,
	}
	if result.relayedBy != "" {
		properties["relayedBy"] = result.relayedBy
		properties["relaySubject"] = result.relaySubject
	}

	reqCtx.SharedContext.AuthContext = &policy.AuthContext{
		Authenticated: true,
		AuthType:      AuthType,
		Subject:       result.subject,
		Issuer:        result.issuerCA,
		CredentialID:  result.credentialID,
		Properties:    properties,
		Previous:      reqCtx.SharedContext.AuthContext,
	}

	// The backend receives at most one certificate header,
	// x-forwarded-client-cert, and it always describes the certificate the
	// caller authenticated with. The relayed header never reaches it.
	action := policy.UpstreamRequestHeaderModifications{}
	switch {
	case !p.forwardCertificate:
		action.HeadersToRemove = []string{xfccHeaderName, p.header.name}
	case result.headerCertificate != nil:
		action.HeadersToSet = map[string]string{xfccHeaderName: envoyXFCC(result.headerCertificate)}
		action.HeadersToRemove = []string{p.header.name}
	case len(reqCtx.DownstreamRequest().Headers.Get(p.header.name)) > 0:
		action.HeadersToRemove = []string{p.header.name}
	}
	return action
}

// setSpanAttributes records the outcome on the per-policy span in ctx. tls is
// read separately because the protocol version belongs to the connection, not
// the evaluated certificate. No attribute ever comes from a PEM, a chain or a
// raw header value.
func setSpanAttributes(ctx context.Context, result evaluationResult, tls *policy.DownstreamTLS) {
	span := trace.SpanFromContext(ctx)
	if !span.IsRecording() {
		return
	}

	outcome := "deny"
	if result.authenticated {
		outcome = "allow"
	}
	attrs := make([]attribute.KeyValue, 0, 10)
	attrs = append(attrs, attribute.String("mtls_auth.result", outcome))
	if result.source != "" {
		attrs = append(attrs, attribute.String("mtls_auth.source", result.source))
	}

	if result.authenticated {
		attrs = append(attrs,
			attribute.Int("mtls_auth.matched_entry", result.entryIndex),
			attribute.String("enduser.id", result.subject),
		)
	} else {
		attrs = append(attrs, attribute.String("mtls_auth.reason", result.reason))
	}
	if result.relayedBy != "" {
		attrs = append(attrs, attribute.String("mtls_auth.relayed_by", result.relayedBy))
	}

	if result.subjectDN != "" {
		attrs = append(attrs, attribute.String("tls.client.subject", result.subjectDN))
	}
	if result.authenticated && result.issuerCA != "" {
		attrs = append(attrs, attribute.String("tls.client.issuer", result.issuerCA))
	}
	if result.credentialID != "" {
		attrs = append(attrs, attribute.String("tls.client.hash.sha256", result.credentialID))
	}
	if !result.notAfter.IsZero() {
		attrs = append(attrs, attribute.String("tls.client.not_after", result.notAfter.UTC().Format(time.RFC3339)))
	}
	if tls != nil && tls.TLSVersion != "" {
		attrs = append(attrs, attribute.String("tls.protocol.version", tls.TLSVersion))
	}

	span.SetAttributes(attrs...)
}

// handleAuthFailure returns the uniform rejection response and records the
// failed attempt on the AuthContext chain. The response never varies by
// reason and carries no WWW-Authenticate header, since mutual TLS has no
// challenge to offer.
func (p *MtlsAuthPolicy) handleAuthFailure(shared *policy.SharedContext, statusCode int, errorFormat, errorMessage string) policy.RequestHeaderAction {
	shared.AuthContext = &policy.AuthContext{
		Authenticated: false,
		AuthType:      AuthType,
		Previous:      shared.AuthContext,
	}

	headers := map[string]string{
		"content-type": "application/json",
	}

	var body string
	switch errorFormat {
	case "plain":
		body = errorMessage
		headers["content-type"] = "text/plain"
	case "minimal":
		body = "Unauthorized"
	default:
		// json.Marshal sorts map keys, so the body is always
		// {"error":...,"message":...}.
		bodyBytes, _ := json.Marshal(map[string]interface{}{
			"error":   "Unauthorized",
			"message": errorMessage,
		})
		body = string(bodyBytes)
	}

	return policy.ImmediateResponse{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       []byte(body),
	}
}

// parseAcceptParam parses the accept param, trimming each ca name and
// normalising thumbprints; absent yields nil. A malformed entry fails
// binding, so a bad narrowing can never widen what an entry accepts.
func parseAcceptParam(raw interface{}) ([]acceptEntry, error) {
	if raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s must be an array", acceptParam)
	}

	entries := make([]acceptEntry, 0, len(items))
	for i, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("%s[%d] must be an object", acceptParam, i)
		}

		ca, _ := obj["ca"].(string)
		entry := acceptEntry{ca: strings.TrimSpace(ca)}
		if entry.ca == "" {
			return nil, fmt.Errorf("%s[%d].ca is required", acceptParam, i)
		}

		if matchRaw, ok := obj["match"]; ok && matchRaw != nil {
			matchObj, ok := matchRaw.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("%s[%d].match must be an object", acceptParam, i)
			}
			matchPath := fmt.Sprintf("%s[%d].match", acceptParam, i)
			var err error
			if entry.uriSANs, err = stringListParam(matchObj, "uriSANs", matchPath); err != nil {
				return nil, err
			}
			if entry.dnsSANs, err = stringListParam(matchObj, "dnsSANs", matchPath); err != nil {
				return nil, err
			}
			// A match that names no SAN would narrow nothing, so it is
			// refused rather than read as "accept the whole authority".
			if len(entry.uriSANs) == 0 && len(entry.dnsSANs) == 0 {
				return nil, fmt.Errorf("%s must list uriSANs or dnsSANs", matchPath)
			}
		}

		thumbs, err := stringListParam(obj, "thumbprints", fmt.Sprintf("%s[%d]", acceptParam, i))
		if err != nil {
			return nil, err
		}
		if thumbsRaw, ok := obj["thumbprints"]; ok && thumbsRaw != nil && len(thumbs) == 0 {
			return nil, fmt.Errorf("%s[%d].thumbprints must list at least one thumbprint", acceptParam, i)
		}
		for k, t := range thumbs {
			normalized := normalizeThumbprint(t)
			if !isSHA256Hex(normalized) {
				return nil, fmt.Errorf("%s[%d].thumbprints[%d] must be a SHA-256 thumbprint of 64 hex characters", acceptParam, i, k)
			}
			entry.thumbprints = append(entry.thumbprints, normalized)
		}

		entries = append(entries, entry)
	}
	return entries, nil
}

// parseHeaderConfig reads the client-certificate header system parameters. A
// missing or malformed value falls back to its default, and every default is
// the restrictive one.
func parseHeaderConfig(params map[string]interface{}) headerConfig {
	cfg := headerConfig{name: defaultHeaderName}
	if name, ok := params[headerNameParam].(string); ok && strings.TrimSpace(name) != "" {
		cfg.name = name
	}
	if trustAny, ok := params[trustAnyParam].(bool); ok {
		cfg.trustAny = trustAny
	}
	return cfg
}

// parseForwardCertificateParam defaults to true and rejects any non-boolean
// value.
func parseForwardCertificateParam(raw interface{}) (bool, error) {
	if raw == nil {
		return true, nil
	}
	forward, ok := raw.(bool)
	if !ok {
		return false, fmt.Errorf("%s must be true or false", forwardCertificateParam)
	}
	return forward, nil
}

// stringListParam reads an optional list of strings. An absent key yields nil
// and a malformed one is an error, so a bad narrowing fails closed.
func stringListParam(obj map[string]interface{}, key, path string) ([]string, error) {
	raw, ok := obj[key]
	if !ok || raw == nil {
		return nil, nil
	}
	items, ok := raw.([]interface{})
	if !ok {
		return nil, fmt.Errorf("%s.%s must be a list of strings", path, key)
	}
	out := make([]string, 0, len(items))
	for j, item := range items {
		str, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s.%s[%d] must be a string", path, key, j)
		}
		out = append(out, str)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// normalizeThumbprint strips a "sha256:" prefix and colon separators and
// lowercases the rest.
// isSHA256Hex reports whether a normalised thumbprint is 64 lowercase hex characters.
func isSHA256Hex(t string) bool {
	if len(t) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(t)
	return err == nil
}

func normalizeThumbprint(t string) string {
	t = strings.ToLower(strings.TrimSpace(t))
	t = strings.TrimPrefix(t, "sha256:")
	t = strings.ReplaceAll(t, ":", "")
	return t
}

// parseCertificatePEM decodes one PEM certificate. Some Envoy builds
// percent-encode connection.peer_certificate, so a value that is not PEM gets
// one percent-decode before failing.
func parseCertificatePEM(pemStr string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil && !strings.Contains(pemStr, "-----BEGIN") {
		if decoded, err := url.PathUnescape(pemStr); err == nil {
			block, _ = pem.Decode([]byte(decoded))
		}
	}
	if block == nil {
		return nil, fmt.Errorf("not a valid PEM block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}
	return cert, nil
}

// decodeHeaderCertificate decodes a header carrying one certificate as plain
// or URL-encoded PEM, PEM with its line breaks collapsed, or bare base64 of
// DER or of unarmored PEM.
func decodeHeaderCertificate(raw string) (*x509.Certificate, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty certificate header value")
	}

	if cert, err := parseCertificatePEM(raw); err == nil {
		return cert, nil
	}

	// parseCertificatePEM skips its percent-decode when a BEGIN marker is
	// present, so decode here too.
	candidate := raw
	if decoded, err := url.PathUnescape(raw); err == nil {
		candidate = decoded
	}
	if cert, err := parseCertificatePEM(candidate); err == nil {
		return cert, nil
	}

	// A header cannot carry a newline, so proxies often send PEM with its line
	// breaks turned into spaces. pem.Decode rejects that, and the base64 branch
	// below would glue the armor into the body, so rebuild the PEM first.
	if cert, ok := decodeSpaceJoinedPEM(candidate); ok {
		return cert, nil
	}

	// Bare base64 body: strip any whitespace/newlines and try every base64
	// variant a caller might reasonably use, decoding first to DER and, if
	// that isn't a certificate, to a PEM document lacking armor.
	stripped := strings.Join(strings.Fields(candidate), "")
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := enc.DecodeString(stripped)
		if err != nil {
			continue
		}
		if cert, err := x509.ParseCertificate(decoded); err == nil {
			return cert, nil
		}
		if block, _ := pem.Decode(decoded); block != nil {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				return cert, nil
			}
		}
	}

	return nil, fmt.Errorf("could not decode certificate header value")
}

// decodeSpaceJoinedPEM decodes PEM whose line breaks were collapsed. When
// several certificates are joined, the first is the identity.
func decodeSpaceJoinedPEM(raw string) (*x509.Certificate, bool) {
	rebuilt := reconstitutePEMArmor(raw)
	if rebuilt == "" {
		return nil, false
	}
	certs := parsePEMCertificates(rebuilt)
	if len(certs) == 0 {
		return nil, false
	}
	return certs[0], true
}

// reconstitutePEMArmor rebuilds newline-delimited PEM from every BEGIN/END
// CERTIFICATE span in raw, re-wrapping each body at 64 columns. It returns ""
// when raw holds no complete span.
func reconstitutePEMArmor(raw string) string {
	const beginMarker = "-----BEGIN CERTIFICATE-----"
	const endMarker = "-----END CERTIFICATE-----"

	var out strings.Builder
	rest := raw
	for {
		beginIdx := strings.Index(rest, beginMarker)
		if beginIdx < 0 {
			break
		}
		afterBegin := rest[beginIdx+len(beginMarker):]
		endIdx := strings.Index(afterBegin, endMarker)
		if endIdx < 0 {
			break
		}
		body := afterBegin[:endIdx]
		stripped := strings.Join(strings.Fields(body), "")

		out.WriteString(beginMarker)
		out.WriteByte('\n')
		for i := 0; i < len(stripped); i += 64 {
			end := i + 64
			if end > len(stripped) {
				end = len(stripped)
			}
			out.WriteString(stripped[i:end])
			out.WriteByte('\n')
		}
		out.WriteString(endMarker)
		out.WriteByte('\n')

		rest = afterBegin[endIdx+len(endMarker):]
	}
	return out.String()
}

// parsePEMCertificates decodes every CERTIFICATE block in data. A block that
// fails to parse is skipped: this is supplementary path-building material
// from a request header, so a bad entry weakens verification rather than
// aborting the request.
func parsePEMCertificates(data string) []*x509.Certificate {
	var certs []*x509.Certificate
	rest := []byte(data)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return certs
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
			certs = append(certs, cert)
		}
	}
}

// envoyXFCC renders leaf as a single x-forwarded-client-cert hop in the form
// the listener's SANITIZE_SET writes with Subject, Cert, URI and DNS details:
// Hash, Cert, Subject, then one URI and one DNS element per SAN. A header
// certificate arrives without a chain, so there is no Chain element.
func envoyXFCC(leaf *x509.Certificate) string {
	var b strings.Builder
	b.WriteString("Hash=")
	b.WriteString(sha256Hex(leaf.Raw))
	b.WriteString(`;Cert="`)
	b.WriteString(xfccPEMEncoder.Replace(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw}))))
	b.WriteString(`";Subject=`)
	b.WriteString(xfccQuoted(leaf.Subject.String()))
	for _, uri := range uriSANStrings(leaf) {
		b.WriteString(";URI=")
		b.WriteString(xfccValue(uri))
	}
	for _, dns := range leaf.DNSNames {
		b.WriteString(";DNS=")
		b.WriteString(xfccValue(dns))
	}
	return b.String()
}

// xfccPEMEncoder percent-encodes PEM text the way Envoy encodes the Cert
// element.
var xfccPEMEncoder = strings.NewReplacer("\n", "%0A", " ", "%20", "+", "%2B", "/", "%2F", "=", "%3D")

// xfccValue returns v bare, as Envoy writes URI and DNS values, unless it
// holds a character that would end or split the element, in which case it is
// quoted so a SAN cannot inject an element of its own.
func xfccValue(v string) string {
	if strings.ContainsAny(v, `;,"`) {
		return xfccQuoted(v)
	}
	return v
}

// xfccQuoted double-quotes v, escaping '"' and '\' as xfccFieldValue expects.
func xfccQuoted(v string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(v) + `"`
}

// parseXFCCChainCertificates parses the certificates in the Chain element of
// an XFCC value. This gateway terminates the client's TLS, so under
// SANITIZE_SET the value is a single hop with no comma-separated list to
// split.
func parseXFCCChainCertificates(xfcc string) []*x509.Certificate {
	value, ok := xfccFieldValue(xfcc, "Chain")
	if !ok || value == "" {
		return nil
	}
	// Percent-decoding only, not query decoding: PEM's base64 alphabet uses '+',
	// which url.QueryUnescape would turn into a space.
	decoded, err := url.PathUnescape(value)
	if err != nil {
		return nil
	}
	return parsePEMCertificates(decoded)
}

// xfccFieldValue returns the value of the named field (case-insensitive) in
// a single XFCC hop entry — a semicolon-separated Key=Value list where a
// value may be double-quoted (required whenever it contains a ';', ',', or
// '"') with '\\'-escaped '"' and '\\' inside the quotes.
func xfccFieldValue(entry, wantKey string) (string, bool) {
	i, n := 0, len(entry)
	for i < n {
		for i < n && entry[i] == ';' {
			i++
		}
		if i >= n {
			break
		}
		eq := strings.IndexByte(entry[i:], '=')
		if eq < 0 {
			break
		}
		key := entry[i : i+eq]
		i += eq + 1

		var value strings.Builder
		if i < n && entry[i] == '"' {
			i++
			for i < n {
				c := entry[i]
				if c == '\\' && i+1 < n {
					value.WriteByte(entry[i+1])
					i += 2
					continue
				}
				if c == '"' {
					i++
					break
				}
				value.WriteByte(c)
				i++
			}
		} else {
			start := i
			for i < n && entry[i] != ';' {
				i++
			}
			value.WriteString(entry[start:i])
		}

		if strings.EqualFold(key, wantKey) {
			return value.String(), true
		}

		for i < n && entry[i] != ';' {
			i++
		}
	}
	return "", false
}

func uriSANStrings(leaf *x509.Certificate) []string {
	if len(leaf.URIs) == 0 {
		return nil
	}
	out := make([]string, len(leaf.URIs))
	for i, u := range leaf.URIs {
		out[i] = u.String()
	}
	return out
}

// firstMatchingSAN returns the first value in accepted that is present among
// candidates, exact string comparison only (no wildcard/pattern matching).
func firstMatchingSAN(candidates []string, accepted []string) string {
	if len(candidates) == 0 || len(accepted) == 0 {
		return ""
	}
	for _, want := range accepted {
		if containsConstantTime(candidates, want) {
			return want
		}
	}
	return ""
}

// containsConstantTime reports whether want is in values, comparing every
// element in constant time so a match position or a shared prefix is not
// observable through timing.
func containsConstantTime(values []string, want string) bool {
	found := 0
	for _, v := range values {
		found |= subtle.ConstantTimeCompare([]byte(v), []byte(want))
	}
	return found == 1
}

func firstOf(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func getIntParam(params map[string]interface{}, key string, def int) int {
	v, ok := params[key]
	if !ok {
		return def
	}
	switch n := v.(type) {
	case int:
		return n
	case int64:
		return int(n)
	case float64:
		return int(n)
	default:
		return def
	}
}

func getStringParam(params map[string]interface{}, key, def string) string {
	v, ok := params[key]
	if !ok {
		return def
	}
	s, ok := v.(string)
	if !ok || s == "" {
		return def
	}
	return s
}
