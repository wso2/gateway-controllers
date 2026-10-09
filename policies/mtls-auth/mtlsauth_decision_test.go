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
	"context"
	"net/url"
	"slices"
	"testing"
	"time"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// reqCtxWithTLSAndHeaderValues is reqCtxWithTLSAndHeader for zero, one or
// several values of the certificate header.
func reqCtxWithTLSAndHeaderValues(tls *policy.DownstreamTLS, headerName string, values ...string) *policy.RequestHeaderContext {
	headers := map[string][]string{}
	if len(values) > 0 {
		headers[headerName] = values
	}
	return &policy.RequestHeaderContext{
		SharedContext: &policy.SharedContext{},
		Method:        "GET",
		Path:          "/protected",
		Downstream: &policy.DownstreamContext{
			TLS:     tls,
			Request: &policy.DownstreamRequest{Headers: policy.NewHeaders(headers)},
		},
	}
}

// TestMtlsAuthPolicy_Evaluate_DecisionTree walks every branch of evaluate's
// decision order and asserts the span attributes that record which
// certificate was evaluated.
func TestMtlsAuthPolicy_Evaluate_DecisionTree(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{uriSANs: []string{"urn:partner-a:payments"}})
	clientAOther := newLeaf(t, rootA, "client-a-other", certOpts{uriSANs: []string{"urn:partner-a:other"}})
	clientAExpired := newLeaf(t, rootA, "client-a-expired", certOpts{
		notBefore: time.Now().Add(-2 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(-1 * 365 * 24 * time.Hour),
	})
	clientANotYetValid := newLeaf(t, rootA, "client-a-not-yet-valid", certOpts{
		notBefore: time.Now().Add(1 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(2 * 365 * 24 * time.Hour),
	})

	rootB := newRootCA(t, "Partner B Root CA")
	clientB := newLeaf(t, rootB, "client-b", certOpts{uriSANs: []string{"urn:partner-b:billing"}})

	unpooledRoot := newRootCA(t, "Unpooled Root CA")
	clientUnpooled := newLeaf(t, unpooledRoot, "client-unpooled", certOpts{})

	relayCA := newRootCA(t, "Edge LB CA")
	edgeLB := newLeaf(t, relayCA, "edge-lb", certOpts{dnsSANs: []string{"edge-lb.internal"}})

	// One pool serves every instance below, as in a running engine. The load
	// balancer's authority is held twice: as a relay and as a client authority.
	publishAuthorities(t,
		authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}},
		authoritySpec{name: "partner-b", role: roleClient, certs: []*testEntity{rootB}},
		authoritySpec{name: "edge-lb-client", role: roleClient, certs: []*testEntity{relayCA}},
		authoritySpec{name: "edge-lb-ca", role: roleRelay, certs: []*testEntity{relayCA}},
	)
	acceptPartnerA := []entrySpec{{ca: "partner-a"}}
	acceptRelayAuthority := []entrySpec{{ca: "edge-lb-client"}}

	relayPolicy := mustPolicy(t, buildParams(acceptPartnerA))
	bypassPolicy := mustPolicy(t, buildParamsWithHeader(acceptPartnerA, map[string]interface{}{"trustAny": true}))
	lbAsClientPolicy := mustPolicy(t, buildParams(acceptRelayAuthority))

	noCertificate := func() *policy.DownstreamTLS { return &policy.DownstreamTLS{MTLS: false} }
	header := func(e *testEntity) string { return url.PathEscape(e.pemCert()) }

	tests := []struct {
		name          string
		policy        *MtlsAuthPolicy
		tls           *policy.DownstreamTLS
		header        []string
		wantAllow     bool
		wantReason    string
		wantSource    string
		wantRelayedBy string
		wantSubject   string
	}{
		// The connection passes accept; the header plays no part.
		{
			name:   "accepted connection, no header",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(clientA, true),
			wantAllow: true, wantSource: sourceHandshake, wantSubject: "urn:partner-a:payments",
		},
		{
			name:   "accepted connection, header carrying another accepted certificate: the connection wins",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(clientA, true), header: []string{header(clientAOther)},
			wantAllow: true, wantSource: sourceHandshake, wantSubject: "urn:partner-a:payments",
		},
		{
			name:   "accepted connection under trustAny, header carrying another accepted certificate: the connection wins",
			policy: bypassPolicy, tls: downstreamTLSFromLeaf(clientA, true), header: []string{header(clientAOther)},
			wantAllow: true, wantSource: sourceHandshake, wantSubject: "urn:partner-a:payments",
		},
		{
			name:   "relay authority also accepted as a client, header present: the load balancer is the caller",
			policy: lbAsClientPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{header(clientA)},
			wantAllow: true, wantSource: sourceHandshake, wantSubject: "edge-lb.internal",
		},

		// The connection did not pass accept; the header is judged.
		{
			name:   "relay connection on an API accepting only partners, header carrying an accepted client: the relayed client",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{header(clientA)},
			wantAllow: true, wantSource: sourceHeader, wantRelayedBy: "edge-lb-ca", wantSubject: "urn:partner-a:payments",
		},
		{
			name:   "relay connection, header carrying an unaccepted client",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{header(clientB)},
			wantReason: reasonAuthorityNotAccepted, wantSource: sourceHeader, wantRelayedBy: "edge-lb-ca",
		},
		{
			name:   "relay connection, header carrying an expired client",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{header(clientAExpired)},
			wantReason: reasonExpired, wantSource: sourceHeader, wantRelayedBy: "edge-lb-ca",
		},
		{
			name:   "relay connection, header carrying a certificate from no pooled authority",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{header(clientUnpooled)},
			wantReason: reasonUntrustedChain, wantSource: sourceHeader, wantRelayedBy: "edge-lb-ca",
		},
		{
			name:   "relay connection, header carrying a certificate from a pooled authority this API does not accept",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{header(clientB)},
			wantReason: reasonAuthorityNotAccepted, wantSource: sourceHeader, wantRelayedBy: "edge-lb-ca",
		},
		{
			name:   "trustAny, no certificate, header carrying a certificate from no pooled authority",
			policy: bypassPolicy, tls: noCertificate(), header: []string{header(clientUnpooled)},
			wantReason: reasonUntrustedChain, wantSource: sourceBypass,
		},
		{
			name:   "relay connection, header is not a certificate",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{"not-a-certificate"},
			wantReason: reasonInvalidCert, wantSource: sourceHeader, wantRelayedBy: "edge-lb-ca",
		},
		{
			name:   "relay connection, header sent twice",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true), header: []string{header(clientA), header(clientAOther)},
			wantReason: reasonInvalidCert, wantSource: sourceHeader, wantRelayedBy: "edge-lb-ca",
		},
		{
			name:   "trustAny, valid unaccepted connection, header carrying an accepted client",
			policy: bypassPolicy, tls: downstreamTLSFromLeaf(clientB, true), header: []string{header(clientA)},
			wantAllow: true, wantSource: sourceBypass, wantSubject: "urn:partner-a:payments",
		},
		{
			name:   "trustAny, valid unaccepted connection, header is not a certificate",
			policy: bypassPolicy, tls: downstreamTLSFromLeaf(clientB, true), header: []string{"not-a-certificate"},
			wantReason: reasonInvalidCert, wantSource: sourceBypass,
		},

		// The connection did not pass accept and the header is not judged.
		{
			name:   "valid non-relay connection not accepted, header ignored",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(clientB, true), header: []string{header(clientA)},
			wantReason: reasonAuthorityNotAccepted, wantSource: sourceHandshake,
		},
		{
			name:   "relay connection, no header: a relay is not a client",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(edgeLB, true),
			wantReason: reasonAuthorityNotAccepted, wantSource: sourceHandshake,
		},

		// No certificate on the connection.
		{
			name:   "trustAny, no certificate, header carrying an accepted client",
			policy: bypassPolicy, tls: noCertificate(), header: []string{header(clientA)},
			wantAllow: true, wantSource: sourceBypass, wantSubject: "urn:partner-a:payments",
		},
		{
			name:   "trustAny, no certificate, header carrying an unaccepted client",
			policy: bypassPolicy, tls: noCertificate(), header: []string{header(clientB)},
			wantReason: reasonAuthorityNotAccepted, wantSource: sourceBypass,
		},
		{
			name:   "trustAny, no certificate, no header",
			policy: bypassPolicy, tls: noCertificate(),
			wantReason: reasonNoCertificate, wantSource: sourceHandshake,
		},
		{
			name:   "relays only, no certificate, header ignored",
			policy: relayPolicy, tls: noCertificate(), header: []string{header(clientA)},
			wantReason: reasonNoCertificate, wantSource: sourceHandshake,
		},

		// Envoy rejected the connection's certificate; a header never rescues it.
		{
			name:   "trustAny, connection certificate from an unpooled authority, header carrying an accepted client",
			policy: bypassPolicy, tls: downstreamTLSFromLeaf(clientUnpooled, false), header: []string{header(clientA)},
			wantReason: reasonUntrustedChain, wantSource: sourceHandshake,
		},
		{
			name:   "trustAny, expired connection certificate, header carrying an accepted client",
			policy: bypassPolicy, tls: downstreamTLSFromLeaf(clientAExpired, false), header: []string{header(clientA)},
			wantReason: reasonExpired, wantSource: sourceHandshake,
		},
		{
			name:   "relay mode, expired connection certificate, header ignored",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(clientAExpired, false), header: []string{header(clientA)},
			wantReason: reasonExpired, wantSource: sourceHandshake,
		},

		// Envoy accepted the connection's certificate but it is unusable in
		// itself; a header never rescues it either.
		{
			name:   "trustAny, expired connection certificate Envoy accepted, header carrying an accepted client",
			policy: bypassPolicy, tls: downstreamTLSFromLeaf(clientAExpired, true), header: []string{header(clientA)},
			wantReason: reasonExpired, wantSource: sourceHandshake,
		},
		{
			name:   "trustAny, not yet valid connection certificate Envoy accepted, header carrying an accepted client",
			policy: bypassPolicy, tls: downstreamTLSFromLeaf(clientANotYetValid, true), header: []string{header(clientA)},
			wantReason: reasonNotYetValid, wantSource: sourceHandshake,
		},
		{
			name:   "trustAny, unparseable connection certificate Envoy accepted, header carrying an accepted client",
			policy: bypassPolicy, tls: &policy.DownstreamTLS{MTLS: true, PeerCertValid: boolPtr(true), PeerCertificatePEM: "not a certificate"}, header: []string{header(clientA)},
			wantReason: reasonInvalidCert, wantSource: sourceHandshake,
		},
		{
			name:   "relay mode, expired connection certificate Envoy accepted, header ignored",
			policy: relayPolicy, tls: downstreamTLSFromLeaf(clientAExpired, true), header: []string{header(clientA)},
			wantReason: reasonExpired, wantSource: sourceHandshake,
		},

		// No verdict at all.
		{
			name:   "trustAny, no TLS attributes, header carrying an accepted client",
			policy: bypassPolicy, tls: nil, header: []string{header(clientA)},
			wantReason: reasonAttributeAbsent, wantSource: sourceHandshake,
		},
		{
			name:   "certificate presented but no Envoy verdict",
			policy: relayPolicy, tls: &policy.DownstreamTLS{MTLS: true, PeerCertificatePEM: clientA.pemCert()},
			wantReason: reasonAttributeAbsent, wantSource: sourceHandshake,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reqCtx := reqCtxWithTLSAndHeaderValues(tc.tls, defaultHeaderName, tc.header...)

			var result evaluationResult
			if tc.wantAllow {
				result = assertAuthenticated(t, tc.policy, reqCtx, 0)
				if result.subject != tc.wantSubject {
					t.Errorf("subject = %q, want %q", result.subject, tc.wantSubject)
				}
			} else {
				assertDenied(t, tc.policy, reqCtx, tc.wantReason)
				result = tc.policy.evaluate(reqCtx, nil)
			}
			if result.source != tc.wantSource {
				t.Errorf("source = %q, want %q", result.source, tc.wantSource)
			}
			if result.relayedBy != tc.wantRelayedBy {
				t.Errorf("relayedBy = %q, want %q", result.relayedBy, tc.wantRelayedBy)
			}
			if tc.wantRelayedBy == "" && result.relaySubject != "" {
				t.Errorf("relaySubject = %q, want empty off the relayed-header path", result.relaySubject)
			}

			_, attrs := callWithRecordedSpan(t, tc.policy, reqCtxWithTLSAndHeaderValues(tc.tls, defaultHeaderName, tc.header...))
			wantResult := "deny"
			if tc.wantAllow {
				wantResult = "allow"
			}
			requireAttrString(t, attrs, "mtls_auth.result", wantResult)
			requireAttrString(t, attrs, "mtls_auth.source", tc.wantSource)
			if tc.wantRelayedBy != "" {
				requireAttrString(t, attrs, "mtls_auth.relayed_by", tc.wantRelayedBy)
			} else {
				requireAttrAbsent(t, attrs, "mtls_auth.relayed_by")
			}
			requireNoPEMLeaked(t, attrs)
		})
	}
}

// TestMtlsAuthPolicy_OnRequestHeaders_ForwardCertificate checks that false
// removes both certificate headers from every allowed request, and that a
// deny carries no header modifications.
func TestMtlsAuthPolicy_OnRequestHeaders_ForwardCertificate(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	clientA := newLeaf(t, rootA, "client-a", certOpts{})
	clientB := newLeaf(t, newRootCA(t, "Partner B Root CA"), "client-b", certOpts{})
	relayCA := newRootCA(t, "Edge LB CA")
	edgeLB := newLeaf(t, relayCA, "edge-lb", certOpts{})

	publishAuthorities(t,
		authoritySpec{name: "partner-a", role: roleClient, certs: []*testEntity{rootA}},
		authoritySpec{name: "edge-lb-ca", role: roleRelay, certs: []*testEntity{relayCA}},
	)
	accept := []entrySpec{{ca: "partner-a"}}

	build := func(t *testing.T, forward interface{}, header map[string]interface{}) *MtlsAuthPolicy {
		t.Helper()
		params := buildParamsWithHeader(accept, header)
		params[forwardCertificateParam] = forward
		return mustPolicy(t, params)
	}
	wantBoth := []string{xfccHeaderName, defaultHeaderName}

	for _, header := range []map[string]interface{}{nil, {"trustAny": true}} {
		t.Run("allowed as the connection removes both headers", func(t *testing.T) {
			p := build(t, false, header)
			action := p.OnRequestHeaders(context.Background(), reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), map[string]interface{}{})
			mods, ok := action.(policy.UpstreamRequestHeaderModifications)
			if !ok {
				t.Fatalf("OnRequestHeaders returned %T, want pass-through", action)
			}
			if !slices.Equal(mods.HeadersToRemove, wantBoth) {
				t.Errorf("HeadersToRemove = %v, want %v", mods.HeadersToRemove, wantBoth)
			}
		})

		t.Run("allowed as the relayed client removes both headers", func(t *testing.T) {
			p := build(t, false, header)
			reqCtx := reqCtxWithTLSAndHeader(downstreamTLSFromLeaf(edgeLB, true), defaultHeaderName, urlEncodedPEMHeaderValue(clientA))
			action := p.OnRequestHeaders(context.Background(), reqCtx, map[string]interface{}{})
			mods, ok := action.(policy.UpstreamRequestHeaderModifications)
			if !ok {
				t.Fatalf("OnRequestHeaders returned %T, want pass-through", action)
			}
			if !slices.Equal(mods.HeadersToRemove, wantBoth) {
				t.Errorf("HeadersToRemove = %v, want %v", mods.HeadersToRemove, wantBoth)
			}
		})
	}

	t.Run("denied request carries no header modifications", func(t *testing.T) {
		p := build(t, false, nil)
		action := p.OnRequestHeaders(context.Background(), reqCtxWithTLS(downstreamTLSFromLeaf(clientB, true)), map[string]interface{}{})
		if _, ok := action.(policy.ImmediateResponse); !ok {
			t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
		}
	})

	t.Run("true removes nothing from a request allowed as the connection", func(t *testing.T) {
		p := build(t, true, nil)
		action := p.OnRequestHeaders(context.Background(), reqCtxWithTLS(downstreamTLSFromLeaf(clientA, true)), map[string]interface{}{})
		if mods := action.(policy.UpstreamRequestHeaderModifications); len(mods.HeadersToRemove) != 0 {
			t.Errorf("HeadersToRemove = %v, want empty", mods.HeadersToRemove)
		}
	})

	for name, value := range map[string]interface{}{"string": "no", "number": 0, "list": []interface{}{false}} {
		t.Run("non-boolean "+name+" fails GetPolicy", func(t *testing.T) {
			params := buildParams(accept)
			params[forwardCertificateParam] = value
			if _, err := GetPolicy(policy.PolicyMetadata{}, params); err == nil {
				t.Fatalf("GetPolicy accepted forwardCertificate = %#v, want an error", value)
			}
		})
	}
}
