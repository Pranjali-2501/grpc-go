/*
 *
 * Copyright 2025 gRPC authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package google

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	grpcbackoff "google.golang.org/grpc/backoff"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/internal/backoff"
	"google.golang.org/grpc/status"
)

type gcpTestAuthInfo struct {
	credentials.CommonAuthInfo
}

func (t *gcpTestAuthInfo) AuthType() string {
	return "test"
}

func TestGcpServiceAccountIdentity_GetRequestMetadata(t *testing.T) {
	// Mock metadata server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Metadata-Flavor") != "Google" {
			http.Error(w, "Missing Metadata-Flavor", http.StatusBadRequest)
			return
		}
		if r.URL.Path != "/computeMetadata/v1/instance/service-accounts/default/identity" {
			http.Error(w, "Not Found", http.StatusNotFound)
			return
		}
		aud := r.URL.Query().Get("audience")
		if aud != "my-audience" {
			http.Error(w, "Wrong Audience", http.StatusBadRequest)
			return
		}

		// Generate a simple JWT
		// Header: {"alg":"none"} -> eyJhbGciOiJub25lIn0
		// Payload: {"exp": <future>}
		exp := time.Now().Add(1 * time.Hour).Unix()
		payload := fmt.Sprintf(`{"exp":%d, "sub": "mock-service-account"}`, exp)
		payload64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
		token := fmt.Sprintf("eyJhbGciOiJub25lIn0.%s.", payload64)
		w.Write([]byte(token))
	}))
	defer ts.Close()

	// Override URL creation in real implementation?
	// The implementation hardcodes "http://metadata.google.internal".
	// We need to inject the client or transport to redirect to mock server.
	// Since we can't easily change the URL in the code without exporting it or using a variable,
	// checking if we can swap the Transport of the client.

	// BUT the URL is absolute in doFetch: "http://metadata.google.internal/..."
	// httptest.Server gives "http://127.0.0.1:port".
	// If we use a custom Transport, we can hijack requests to metadata.google.internal.

	creds, err := NewGcpServiceAccountIdentity("my-audience")
	impl := creds.(*gcpServiceAccountIdentityCallCreds)

	// Inject mock transport
	impl.client.Transport = &mockTransport{
		targetHost: "metadata.google.internal",
		handler:    ts.Listener.Addr().String(), // use the mock server address
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	ctx = credentials.NewContextWithRequestInfo(ctx, credentials.RequestInfo{
		AuthInfo: &gcpTestAuthInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}},
	})

	md, err := creds.GetRequestMetadata(ctx, "uri")
	if err != nil {
		t.Fatalf("GetRequestMetadata failed: %v", err)
	}

	if got, want := md["authorization"], "Bearer eyJhbGci"; len(got) < len(want) || got[:len(want)] != want {
		t.Errorf("GetRequestMetadata returned %q, want prefix %q", got, want)
	}
}

type mockTransport struct {
	targetHost string
	handler    string // address of real handler
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host != m.targetHost {
		return nil, fmt.Errorf("unexpected host: %v", req.URL.Host)
	}
	// Rewrite to local mock server
	newURL := *req.URL
	newURL.Scheme = "http"
	newURL.Host = m.handler

	newReq, _ := http.NewRequestWithContext(req.Context(), req.Method, newURL.String(), req.Body)
	newReq.Header = req.Header
	return http.DefaultTransport.RoundTrip(newReq)
}

func TestGcpServiceAccountIdentity_Backoff(t *testing.T) {
	// Test error handling and backoff
	// We mock a server that initially fails then succeeds

	failures := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failures < 2 {
			failures++
			http.Error(w, "Unavailable", http.StatusServiceUnavailable) // 503
			return
		}
		// Success
		exp := time.Now().Add(1 * time.Hour).Unix()
		payload := fmt.Sprintf(`{"exp":%d}`, exp)
		payload64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
		w.Write([]byte(fmt.Sprintf("H.%s.S", payload64)))
	}))
	defer ts.Close()

	creds, err := NewGcpServiceAccountIdentity("aud")
	impl := creds.(*gcpServiceAccountIdentityCallCreds)
	impl.backoff = backoff.Exponential{Config: grpcbackoff.Config{BaseDelay: 10 * time.Millisecond, Multiplier: 1.0, Jitter: 0.1, MaxDelay: 100 * time.Millisecond}}
	impl.client.Transport = &mockTransport{
		targetHost: "metadata.google.internal",
		handler:    ts.Listener.Addr().String(),
	}

	ctx := credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{
		AuthInfo: &gcpTestAuthInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}},
	})

	// 1st attempt -> fail
	_, err = creds.GetRequestMetadata(ctx)
	if status.Code(err) != codes.Unavailable {
		t.Errorf("Expected Unavailable, got %v", err)
	}

	// 2nd attempt -> fail (cached error if in backoff?)
	// If backoff is small, we might retry.
	// But our mock backoff is 10ms.

	// Wait specifically for success
	// We might need to loop or sleep
	time.Sleep(50 * time.Millisecond)

	// Eventual success
	for i := 0; i < 5; i++ {
		_, err = creds.GetRequestMetadata(ctx)
		if err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Errorf("Expected success after retries, got %v", err)
	}
}

func TestGcpServiceAccountIdentity_Concurrent(t *testing.T) {
	// Test that multiple concurrent calls trigger only one fetch
	fetchedCount := 0
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchedCount++
		// Simulate network delay to ensure concurrency hits the lock/cond logic
		time.Sleep(100 * time.Millisecond)

		exp := time.Now().Add(1 * time.Hour).Unix()
		payload := fmt.Sprintf(`{"exp":%d}`, exp)
		payload64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
		w.Write([]byte(fmt.Sprintf("H.%s.S", payload64)))
	}))
	defer ts.Close()

	creds, _ := NewGcpServiceAccountIdentity("aud")
	impl := creds.(*gcpServiceAccountIdentityCallCreds)
	// Reset backoff to avoid any backoff logic interfering
	impl.client.Transport = &mockTransport{
		targetHost: "metadata.google.internal",
		handler:    ts.Listener.Addr().String(),
	}

	concurrency := 10
	errCh := make(chan error, concurrency)
	startCh := make(chan struct{})

	for i := 0; i < concurrency; i++ {
		go func() {
			<-startCh // sync start
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			ctx = credentials.NewContextWithRequestInfo(ctx, credentials.RequestInfo{
				AuthInfo: &gcpTestAuthInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}},
			})
			_, err := creds.GetRequestMetadata(ctx)
			errCh <- err
		}()
	}

	close(startCh)

	for i := 0; i < concurrency; i++ {
		if err := <-errCh; err != nil {
			t.Errorf("Concurrent GetRequestMetadata failed: %v", err)
		}
	}

	if fetchedCount != 1 {
		t.Errorf("Expected exactly 1 fetch, got %d", fetchedCount)
	}
}

func TestGcpServiceAccountIdentity_ContextTimeout(t *testing.T) {
	// Test that if a fetch is in progress, other RPCs respect their deadline
	fetchStarted := make(chan struct{})
	fetchRelease := make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(fetchStarted)
		<-fetchRelease // Block until test allows proceeding

		exp := time.Now().Add(1 * time.Hour).Unix()
		payload := fmt.Sprintf(`{"exp":%d}`, exp)
		payload64 := base64.RawURLEncoding.EncodeToString([]byte(payload))
		w.Write([]byte(fmt.Sprintf("H.%s.S", payload64)))
	}))
	defer ts.Close()

	creds, _ := NewGcpServiceAccountIdentity("aud")
	impl := creds.(*gcpServiceAccountIdentityCallCreds)
	impl.client.Transport = &mockTransport{
		targetHost: "metadata.google.internal",
		handler:    ts.Listener.Addr().String(),
	}

	// 1. Start a "slow" fetch
	go func() {
		ctx := credentials.NewContextWithRequestInfo(context.Background(), credentials.RequestInfo{
			AuthInfo: &gcpTestAuthInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}},
		})
		creds.GetRequestMetadata(ctx)
	}()

	// Wait for fetch to actually start (and thus create the channel)
	<-fetchStarted

	// 2. Start a second call with a short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	ctx = credentials.NewContextWithRequestInfo(ctx, credentials.RequestInfo{
		AuthInfo: &gcpTestAuthInfo{credentials.CommonAuthInfo{SecurityLevel: credentials.PrivacyAndIntegrity}},
	})

	start := time.Now()
	_, err := creds.GetRequestMetadata(ctx)
	duration := time.Since(start)

	// Release the stuck fetch
	close(fetchRelease)

	// 3. Verify behavior
	if err == nil {
		t.Fatal("Expected context timeout, got nil error")
	}
	if duration > 500*time.Millisecond {
		t.Errorf("GetRequestMetadata blocked for %v, expected ~100ms", duration)
	}
}
