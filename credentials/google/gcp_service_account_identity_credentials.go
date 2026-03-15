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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/internal/backoff"
	"google.golang.org/grpc/internal/status"
)

const (
	// HTTP request timeout set on the http.Client used to make GCP requests.
	gcpRequestTimeout = 5 * time.Second
	// If lifetime left in a cached token is lesser than this value, we fetch a
	// new one.
	minCachedTokenLifetime = time.Minute
)

type gcpServiceAccountIdentityCallCreds struct {
	audience string
	client   *http.Client
	backoff  backoff.Strategy

	mu sync.Mutex
	// state
	token       string
	tokenExpiry time.Time // When the token actually expires
	refreshTime time.Time // When we should soft-refresh
	// inflight/error state
	// fetching is used to coalesce concurrent requests to fetch the token.
	// It is closed when the fetch completes.
	fetching      chan struct{}
	nextRetryTime time.Time // When we can try next (backoff)
	retryAttempt  int       // consecutive failures
	lastErr       error     // error from last attempt
}

// jwtClaims represents the JWT claims structure for extracting expiration time.
type jwtClaims struct {
	Exp int64 `json:"exp"`
}

// NewGcpServiceAccountIdentity creates a PerRPCCredentials that authenticates
// using a GCP Service Account Identity JWT token for the given audience.
//
// It fetches tokens from the GCE metadata server. This is only valid to use if
// your program is running on a GCE instance or an environment with a compatible
// metadata server.
func NewGcpServiceAccountIdentity(audience string) (credentials.PerRPCCredentials, error) {
	if audience == "" {
		return nil, fmt.Errorf("audience cannot be empty")
	}

	return &gcpServiceAccountIdentityCallCreds{
		audience: audience,
		client: &http.Client{
			Timeout: gcpRequestTimeout,
		},
		backoff: backoff.DefaultExponential,
	}, nil
}

// GetRequestMetadata gets the current request metadata, refreshing tokens if
// required. This implementation follows the PerRPCCredentials interface.  The
// tokens will get automatically refreshed if they are about to expire or if
// they haven't been loaded successfully yet.
// If it's not possible to extract a token from the file, UNAVAILABLE is
// returned.
// If the token is extracted but invalid, then UNAUTHENTICATED is returned.
// If errors are encoutered, a backoff is applied before retrying.
func (c *gcpServiceAccountIdentityCallCreds) GetRequestMetadata(ctx context.Context, _ ...string) (map[string]string, error) {
	ri, _ := credentials.RequestInfoFromContext(ctx)
	if err := credentials.CheckSecurityLevel(ri.AuthInfo, credentials.PrivacyAndIntegrity); err != nil {
		return nil, fmt.Errorf("cannot send secure credentials on an insecure connection: %v", err)
	}

	c.mu.Lock()
	// No defer c.mu.Unlock() intentionally to allow manual unlock before fetch

	if c.isTokenValidLocked() {
		if time.Until(c.tokenExpiry) < minCachedTokenLifetime && c.fetching == nil {
			// The token is still valid but is nearing expiration. Trigger a
			// background refresh if one is not already in progress.
			c.fetching = make(chan struct{})
			go c.refreshToken(ctx)
		}
		c.mu.Unlock()
		return map[string]string{
			"authorization": "Bearer " + c.token,
		}, nil
	}

	// If in backoff state, just return the cached error.
	if c.lastErr != nil && time.Now().Before(c.nextRetryTime) {
		err := c.lastErr
		c.mu.Unlock()
		return nil, err
	}

	// At this point, the token is either invalid or expired and we are no
	// longer backing off from any encountered errors.

	for {
		if c.fetching == nil {
			// We are the one responsible for fetching.
			c.fetching = make(chan struct{})
			// Unlock while fetching to allow other RPCs to pile up on the
			// fetching channel.
			c.mu.Unlock()

			token, expiry, err := c.fetchIdentityToken(ctx)

			c.mu.Lock()
			// Update cache and signal completion.
			c.updateCacheLocked(token, expiry, err)
			close(c.fetching)
			c.fetching = nil
			// After fetching, we loop back to check if the token is valid.
			// It might still be invalid if the fetch failed.
		} else {
			// A fetch is already in progress, wait for it or the context.
			wait := c.fetching
			c.mu.Unlock()
			select {
			case <-wait:
			case <-ctx.Done():
				// c.mu is already unlocked here
				return nil, ctx.Err()
			}
			c.mu.Lock()
		}

		// Re-check validity after waking up
		if c.isTokenValidLocked() {
			c.mu.Unlock()
			return map[string]string{
				"authorization": "Bearer " + c.token,
			}, nil
		}
		if c.lastErr != nil && time.Now().Before(c.nextRetryTime) {
			err := c.lastErr
			c.mu.Unlock()
			return nil, err
		}
	}
}

// fetchIdentityToken makes an HTTP request to the GCE metadata server to fetch
// a new identity token for the configured audience.
func (g *gcpServiceAccountIdentityCallCreds) fetchIdentityToken(ctx context.Context) (string, time.Time, error) {
	url := fmt.Sprintf("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s", g.audience)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create http request: %v", err)
	}
	req.Header.Set("Metadata-Flavor", "Google")

	// http.Client returns a non-nil error only if it encounters an error
	// caused by client policy, or failure to speak HTTP (such as a network
	// connectivity problem).
	resp, err := g.client.Do(req)
	if err != nil {
		return "", time.Time{}, status.Errorf(codes.Unavailable, "failed with I/O error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode == http.StatusServiceUnavailable || resp.StatusCode == http.StatusBadGateway || resp.StatusCode == http.StatusGatewayTimeout {
			return "", time.Time{}, status.Errorf(codes.Unavailable, "failed to fetch token with status: %v", resp.StatusCode)
		}
		return "", time.Time{}, status.Errorf(codes.Unauthenticated, "failed to fetch token with status: %v", resp.StatusCode)
	}

	// When the http.Client returns a non-nil error, it is the
	// responsibility of the caller to read the response body till an EOF is
	// encountered and to close it.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to read response body: %v", err)
	}

	expiry, err := g.extractExpiration(string(body))
	if err != nil {
		return "", time.Time{}, err
	}

	return string(body), expiry, nil
}

// extractClaimsRaw returns the JWT's claims part as raw string. Even though the
// header and signature are not used, it still expects that the input string to
// be well-formed (ie comprised of exactly three parts, separated by a dot
// character).
func extractClaimsRaw(s string) (string, bool) {
	const tokenDelim = "."
	_, s, ok := strings.Cut(s, tokenDelim)
	if !ok { // no period found
		return "", false
	}
	claims, s, ok := strings.Cut(s, tokenDelim)
	if !ok { // only one period found
		return "", false
	}
	_, _, ok = strings.Cut(s, tokenDelim)
	if ok { // three periods found
		return "", false
	}
	return claims, true
}

// extractExpiration parses the JWT token to extract the expiration time.
func (g *gcpServiceAccountIdentityCallCreds) extractExpiration(token string) (time.Time, error) {
	claimsRaw, ok := extractClaimsRaw(token)
	if !ok {
		return time.Time{}, fmt.Errorf("expected 3 parts in token")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(claimsRaw)
	if err != nil {
		return time.Time{}, fmt.Errorf("decode error: %v", err)
	}

	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return time.Time{}, fmt.Errorf("unmarshal error: %v", err)
	}

	if claims.Exp == 0 {
		return time.Time{}, fmt.Errorf("no expiration claims")
	}

	expTime := time.Unix(claims.Exp, 0)

	// Check if token is already expired.
	if expTime.Before(time.Now()) {
		return time.Time{}, fmt.Errorf("expired token")
	}

	return expTime, nil
}

// RequireTransportSecurity indicates whether the credentials requires
// transport security.
func (c *gcpServiceAccountIdentityCallCreds) RequireTransportSecurity() bool {
	return true
}

// isTokenValidLocked checks if the cached token is still valid.
// Caller must hold c.mu lock.
func (c *gcpServiceAccountIdentityCallCreds) isTokenValidLocked() bool {
	if c.token == "" {
		return false
	}
	return c.tokenExpiry.After(time.Now())
}

// refreshToken fetches a new token from the GCP metadata server and updates
// the cache.
func (c *gcpServiceAccountIdentityCallCreds) refreshToken(ctx context.Context) {
	// Do not hold the lock while making the network request. This allows other
	// RPCs to proceed (using the cached token if valid) while we fetch a new
	// one. This aligns with gRPC A83.
	token, expiry, err := c.fetchIdentityToken(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.updateCacheLocked(token, expiry, err)
	if c.fetching != nil {
		close(c.fetching)
		c.fetching = nil
	}
}

// updateCacheLocked updates the cached token, expiry, and error state.
// If an error is provided, it determines whether to set it as an UNAVAILABLE
// or UNAUTHENTICATED error based on the error type.
// NOTE: This method (and its callers) do not queue up a token refresh/retry if
// the expiration is soon / an error was encountered. Instead, this is done when
// handling RPCs. This is as per gRFC A97, which states that it is
// undesirable to retry loading the token if the channel is idle.
// Caller must hold c.mu lock.
func (c *gcpServiceAccountIdentityCallCreds) updateCacheLocked(token string, expiry time.Time, err error) {
	if err != nil {
		// Convert to gRPC status codes
		c.lastErr = err
		backoffDelay := c.backoff.Backoff(c.retryAttempt)
		c.retryAttempt++
		c.nextRetryTime = time.Now().Add(backoffDelay)
		return
	}
	// Success - clear any cached error and update token cache
	c.lastErr = nil
	c.retryAttempt = 0
	c.nextRetryTime = time.Time{}

	c.token = token
	// Per gRFC A83: consider token invalid if it expires within the next 30
	// seconds to accommodate for clock skew and server processing time.
	c.tokenExpiry = expiry.Add(-30 * time.Second)
}
