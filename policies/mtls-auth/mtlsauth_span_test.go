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
	"log/slog"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	policy "github.com/wso2/api-platform/sdk/core/policy/v1alpha2"
)

// callWithRecordedSpan runs OnRequestHeaders with a recording span in its
// context, as the executor's per-policy span would be, and returns the action
// and the span's final attributes.
func callWithRecordedSpan(t *testing.T, p *MtlsAuthPolicy, reqCtx *policy.RequestHeaderContext) (policy.RequestHeaderAction, []attribute.KeyValue) {
	t.Helper()
	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	ctx, span := tp.Tracer("test").Start(context.Background(), "test-span")
	action := p.OnRequestHeaders(ctx, reqCtx, map[string]interface{}{})
	span.End()

	ended := sr.Ended()
	if len(ended) != 1 {
		t.Fatalf("expected exactly 1 ended span, got %d", len(ended))
	}
	return action, ended[0].Attributes()
}

// attrValue returns the value of the first attribute in attrs named key.
func attrValue(attrs []attribute.KeyValue, key string) (attribute.Value, bool) {
	for _, a := range attrs {
		if string(a.Key) == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

func requireAttrString(t *testing.T, attrs []attribute.KeyValue, key, want string) {
	t.Helper()
	v, ok := attrValue(attrs, key)
	if !ok {
		t.Fatalf("expected span attribute %q to be set", key)
		return
	}
	if got := v.AsString(); got != want {
		t.Errorf("span attribute %q = %q, want %q", key, got, want)
	}
}

func requireAttrAbsent(t *testing.T, attrs []attribute.KeyValue, key string) {
	t.Helper()
	if _, ok := attrValue(attrs, key); ok {
		t.Errorf("expected span attribute %q to be absent", key)
	}
}

// requireNoPEMLeaked fails if any attribute value holds PEM armor or the
// certificate content.
func requireNoPEMLeaked(t *testing.T, attrs []attribute.KeyValue) {
	t.Helper()
	for _, a := range attrs {
		if strings.Contains(a.Value.Emit(), "BEGIN CERTIFICATE") {
			t.Errorf("span attribute %q leaked PEM content: %q", a.Key, a.Value.Emit())
		}
	}
}

func TestMtlsAuthPolicy_SpanAttributes_Allow(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{uriSANs: []string{"urn:partner-a:payments"}})
	entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}}
	p := mustBuildPolicy(t, []*testEntity{rootA}, entries)

	tls := downstreamTLSFromLeaf(leaf, true)
	tls.TLSVersion = "TLSv1.3"
	reqCtx := reqCtxWithTLS(tls)

	action, attrs := callWithRecordedSpan(t, p, reqCtx)
	if _, ok := action.(policy.UpstreamRequestHeaderModifications); !ok {
		t.Fatalf("OnRequestHeaders returned %T, want a pass-through action", action)
	}

	requireAttrString(t, attrs, "mtls_auth.result", "allow")
	requireAttrString(t, attrs, "mtls_auth.source", sourceHandshake)
	requireAttrString(t, attrs, "enduser.id", "urn:partner-a:payments")
	requireAttrString(t, attrs, "tls.client.subject", leaf.cert.Subject.String())
	requireAttrString(t, attrs, "tls.client.issuer", "auth-ca-a")
	requireAttrString(t, attrs, "tls.client.hash.sha256", leaf.thumbprint())
	requireAttrString(t, attrs, "tls.protocol.version", "TLSv1.3")
	requireAttrAbsent(t, attrs, "mtls_auth.reason")

	v, ok := attrValue(attrs, "mtls_auth.matched_entry")
	if !ok || v.AsInt64() != 0 {
		t.Errorf("mtls_auth.matched_entry = %v (ok=%v), want 0", v, ok)
	}
	if _, ok := attrValue(attrs, "tls.client.not_after"); !ok {
		t.Errorf("expected tls.client.not_after to be set")
	}
	requireNoPEMLeaked(t, attrs)
}

func TestMtlsAuthPolicy_SpanAttributes_DenyReasons(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	unrelatedRoot := newRootCA(t, "Unrelated Root CA")

	expiredLeaf := newLeaf(t, rootA, "client-expired", certOpts{
		notBefore: time.Now().Add(-2 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(-1 * 365 * 24 * time.Hour),
	})
	notYetValidLeaf := newLeaf(t, rootA, "client-not-yet-valid", certOpts{
		notBefore: time.Now().Add(1 * 365 * 24 * time.Hour),
		notAfter:  time.Now().Add(11 * 365 * 24 * time.Hour),
	})
	wrongCALeaf := newLeaf(t, unrelatedRoot, "client-wrong-ca", certOpts{})
	untrustedChainLeaf := newLeaf(t, unrelatedRoot, "client-untrusted-chain", certOpts{})
	garbageTLS := downstreamTLSFromLeaf(wrongCALeaf, true)
	garbageTLS.PeerCertificatePEM = "not a certificate"

	entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}}}

	tests := []struct {
		name       string
		reqCtx     *policy.RequestHeaderContext
		wantReason string
		wantLeaf   bool // whether tls.client.* attributes should be present
	}{
		{
			name:       "attribute absent (no TLS at all)",
			reqCtx:     reqCtxWithTLS(nil),
			wantReason: reasonAttributeAbsent,
			wantLeaf:   false,
		},
		{
			name:       "no certificate presented",
			reqCtx:     reqCtxWithTLS(&policy.DownstreamTLS{MTLS: false}),
			wantReason: reasonNoCertificate,
			wantLeaf:   false,
		},
		{
			name:       "expired",
			reqCtx:     reqCtxWithTLS(downstreamTLSFromLeaf(expiredLeaf, true)),
			wantReason: reasonExpired,
			wantLeaf:   true,
		},
		{
			name:       "not yet valid",
			reqCtx:     reqCtxWithTLS(downstreamTLSFromLeaf(notYetValidLeaf, true)),
			wantReason: reasonNotYetValid,
			wantLeaf:   true,
		},
		{
			name:       "authority not accepted",
			reqCtx:     reqCtxWithTLS(downstreamTLSFromLeaf(wrongCALeaf, true)),
			wantReason: reasonAuthorityNotAccepted,
			wantLeaf:   true,
		},
		{
			name:       "untrusted chain (Envoy already rejected, no path to any pool authority)",
			reqCtx:     reqCtxWithTLS(downstreamTLSFromLeaf(untrustedChainLeaf, false)),
			wantReason: reasonUntrustedChain,
			wantLeaf:   true,
		},
		{
			name:       "invalid certificate (unparsable PEM)",
			reqCtx:     reqCtxWithTLS(garbageTLS),
			wantReason: reasonInvalidCert,
			wantLeaf:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
			action, attrs := callWithRecordedSpan(t, p, tt.reqCtx)
			if _, ok := action.(policy.ImmediateResponse); !ok {
				t.Fatalf("OnRequestHeaders returned %T, want policy.ImmediateResponse", action)
			}

			requireAttrString(t, attrs, "mtls_auth.result", "deny")
			requireAttrString(t, attrs, "mtls_auth.reason", tt.wantReason)
			requireAttrAbsent(t, attrs, "mtls_auth.matched_entry")
			requireAttrAbsent(t, attrs, "enduser.id")
			requireAttrAbsent(t, attrs, "tls.client.issuer")

			if tt.wantLeaf {
				if _, ok := attrValue(attrs, "tls.client.subject"); !ok {
					t.Errorf("expected tls.client.subject to be set for a parsed-but-denied certificate")
				}
				if _, ok := attrValue(attrs, "tls.client.hash.sha256"); !ok {
					t.Errorf("expected tls.client.hash.sha256 to be set for a parsed-but-denied certificate")
				}
				if _, ok := attrValue(attrs, "tls.client.not_after"); !ok {
					t.Errorf("expected tls.client.not_after to be set for a parsed-but-denied certificate")
				}
			} else {
				requireAttrAbsent(t, attrs, "tls.client.subject")
				requireAttrAbsent(t, attrs, "tls.client.hash.sha256")
			}
			requireNoPEMLeaked(t, attrs)
		})
	}
}

func TestMtlsAuthPolicy_SpanAttributes_SANAndThumbprintMismatch(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{})
	other := newLeaf(t, rootA, "client-other", certOpts{})

	t.Run("san_mismatch", func(t *testing.T) {
		entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		_, attrs := callWithRecordedSpan(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true)))
		requireAttrString(t, attrs, "mtls_auth.reason", reasonSANMismatch)
		requireNoPEMLeaked(t, attrs)
	})

	t.Run("thumbprint_mismatch", func(t *testing.T) {
		entries := []entrySpec{{ca: "auth-ca-a", roots: []*testEntity{rootA}, thumbprints: []string{other.thumbprint()}}}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		_, attrs := callWithRecordedSpan(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true)))
		requireAttrString(t, attrs, "mtls_auth.reason", reasonThumbprintMismatch)
		requireNoPEMLeaked(t, attrs)
	})
}

// TestMtlsAuthPolicy_Evaluate_MostSpecificReasonAcrossEntries guards that a
// deny reports the most specific rejection across all entries, whatever
// order they are declared in.
func TestMtlsAuthPolicy_Evaluate_MostSpecificReasonAcrossEntries(t *testing.T) {
	rootA := newRootCA(t, "Partner A Root CA")
	rootX := newRootCA(t, "Unrelated Root CA")
	leaf := newLeaf(t, rootA, "client-valid", certOpts{})
	other := newLeaf(t, rootA, "client-other", certOpts{})

	t.Run("authority mismatch then SAN mismatch: overall san_mismatch", func(t *testing.T) {
		entries := []entrySpec{
			{ca: "auth-ca-x", roots: []*testEntity{rootX}},                                              // authority never matches this leaf
			{ca: "auth-ca-a", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}, // authority matches, SAN doesn't
		}
		p := mustBuildPolicy(t, []*testEntity{rootA, rootX}, entries)
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true)), reasonSANMismatch)
	})

	t.Run("SAN mismatch then thumbprint mismatch: overall thumbprint_mismatch", func(t *testing.T) {
		entries := []entrySpec{
			{ca: "auth-ca-a-san", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}, // authority matches, SAN doesn't
			{ca: "auth-ca-a-thumb", roots: []*testEntity{rootA}, thumbprints: []string{other.thumbprint()}}, // authority+SAN match, thumbprint doesn't
		}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true)), reasonThumbprintMismatch)
	})

	t.Run("thumbprint mismatch then SAN mismatch (reverse order): still thumbprint_mismatch", func(t *testing.T) {
		entries := []entrySpec{
			{ca: "auth-ca-a-thumb", roots: []*testEntity{rootA}, thumbprints: []string{other.thumbprint()}}, // authority+SAN match, thumbprint doesn't
			{ca: "auth-ca-a-san", roots: []*testEntity{rootA}, uriSANs: []string{"urn:partner-a:payments"}}, // authority matches, SAN doesn't — must not downgrade
		}
		p := mustBuildPolicy(t, []*testEntity{rootA}, entries)
		assertDenied(t, p, reqCtxWithTLS(downstreamTLSFromLeaf(leaf, true)), reasonThumbprintMismatch)
	})
}

// captureSlog redirects the default slog logger to a buffer for the duration
// of fn, since this policy logs through the package-level slog functions.
func captureSlog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	defer slog.SetDefault(prev)
	fn()
	return buf.String()
}
