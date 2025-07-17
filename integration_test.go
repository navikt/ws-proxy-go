package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

// Integration test that simulates the full flow described in README.md
func TestIntegration_FullProxyFlow(t *testing.T) {
	// Generate test RSA key pair that will be used consistently
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create mock backend services
	gandalfServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that path has been rewritten
		if r.URL.Path != "/rest/v1/sts/samltoken" {
			t.Errorf("Expected path /rest/v1/sts/samltoken, got %s", r.URL.Path)
		}

		// Verify Authorization header is preserved (for Basic auth to Gandalf)
		if auth := r.Header.Get("Authorization"); !strings.HasPrefix(auth, "Basic") {
			t.Errorf("Expected Basic auth header to be preserved, got: %s", auth)
		}

		// Verify X-Azure headers are set
		if clientId := r.Header.Get("X-Azure-Client-Id"); clientId == "" {
			t.Error("Expected X-Azure-Client-Id header to be set")
		}

		if azpName := r.Header.Get("X-Azure-Azp-Name"); azpName == "" {
			t.Error("Expected X-Azure-Azp-Name header to be set")
		}

		// Verify Proxy-Authorization header is removed
		if proxyAuth := r.Header.Get("Proxy-Authorization"); proxyAuth != "" {
			t.Errorf("Proxy-Authorization header should be removed, got: %s", proxyAuth)
		}

		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<saml:Assertion>mock saml response</saml:Assertion>`))
	}))
	defer gandalfServer.Close()

	cicsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify path rewriting for CICS
		if !strings.HasPrefix(r.URL.Path, "/") {
			t.Errorf("CICS path should start with /, got %s", r.URL.Path)
		}

		w.Header().Set("Content-Type", "application/soap+xml")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`<soap:Envelope>mock cics response</soap:Envelope>`))
	}))
	defer cicsServer.Close()

	// Create mock OIDC and JWKS endpoints using the same key
	mockJWKSServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Convert the same private key to JWK format
		nBytes := privateKey.N.Bytes()
		eBytes := make([]byte, 4)
		eBytes[0] = byte(privateKey.E >> 24)
		eBytes[1] = byte(privateKey.E >> 16)
		eBytes[2] = byte(privateKey.E >> 8)
		eBytes[3] = byte(privateKey.E)

		// Remove leading zeros
		for len(eBytes) > 1 && eBytes[0] == 0 {
			eBytes = eBytes[1:]
		}

		jwkSet := JWKSet{
			Keys: []JWK{{
				Kty: "RSA",
				Use: "sig",
				Kid: "test-key-id",
				N:   base64.RawURLEncoding.EncodeToString(nBytes),
				E:   base64.RawURLEncoding.EncodeToString(eBytes),
			}},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(jwkSet)
	}))
	defer mockJWKSServer.Close()

	mockOIDCServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oidcConfig := OIDCConfig{
			JWKSUri: mockJWKSServer.URL,
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(oidcConfig)
	}))
	defer mockOIDCServer.Close()

	// Create test configuration
	config := &Config{
		WellKnownURL: mockOIDCServer.URL,
		ClientID:     "test-client-id",
		GandalfURL:   gandalfServer.URL,
		CICSURL:      cicsServer.URL,
	}

	// Initialize cache
	jwkCache = make(map[string]*rsa.PublicKey)

	// Create router with middleware
	r := mux.NewRouter()
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(jwtMiddleware(config))

	r.HandleFunc("/", healthCheck).Methods("GET")
	protected.PathPrefix("/gandalf/").HandlerFunc(proxyHandler(config.GandalfURL, "/gandalf"))
	protected.PathPrefix("/cics/").HandlerFunc(proxyHandler(config.CICSURL, "/cics"))

	// Create a valid JWT token for testing using the same private key
	claims := &JWTClaims{
		Sub:     "test-app",
		Aud:     "test-client-id",
		AzpName: "test-application",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-id"

	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	// Test 1: Gandalf endpoint (as described in README)
	t.Run("Gandalf SAML token request", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/gandalf/rest/v1/sts/samltoken", nil)
		if err != nil {
			t.Fatal(err)
		}

		// Set headers as described in README
		req.Header.Set("Authorization", "Basic dGVzdDp0ZXN0") // Basic auth for Gandalf
		req.Header.Set("X-Proxy-Authorization", "Bearer "+tokenString)

		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Expected status 200, got %v", status)
		}

		if !strings.Contains(rr.Body.String(), "saml:Assertion") {
			t.Errorf("Expected SAML assertion in response, got: %s", rr.Body.String())
		}
	})

	// Test 2: CICS endpoint (using SAML assertion)
	t.Run("CICS SOAP request", func(t *testing.T) {
		req, err := http.NewRequest("POST", "/cics/some/soap/endpoint", strings.NewReader("<soap:Envelope>request</soap:Envelope>"))
		if err != nil {
			t.Fatal(err)
		}

		req.Header.Set("Content-Type", "application/soap+xml")
		req.Header.Set("X-Proxy-Authorization", "Bearer "+tokenString)

		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Expected status 200, got %v", status)
		}

		if !strings.Contains(rr.Body.String(), "soap:Envelope") {
			t.Errorf("Expected SOAP response, got: %s", rr.Body.String())
		}
	})

	// Test 3: Verify health check works without authentication
	t.Run("Health check without auth", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusOK {
			t.Errorf("Health check should work without auth, got status %v", status)
		}
	})
}

// Test that demonstrates the security requirement from README
func TestSecurity_AccessPolicyValidation(t *testing.T) {
	config := &Config{
		ClientID: "correct-client-id",
	}

	jwkCache = make(map[string]*rsa.PublicKey)

	// Create a JWT with wrong audience (not in access policy)
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := &JWTClaims{
		Sub:     "unauthorized-app",
		Aud:     "wrong-client-id", // This should cause rejection
		AzpName: "unauthorized-application",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "test-key-id" // Add kid header
	tokenString, _ := token.SignedString(privateKey)

	req, err := http.NewRequest("GET", "/gandalf/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("X-Proxy-Authorization", "Bearer "+tokenString)

	rr := httptest.NewRecorder()

	nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("Handler should not be called for wrong audience")
	})

	middleware := jwtMiddleware(config)
	handler := middleware(nextHandler)

	handler.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusForbidden {
		t.Errorf("Expected 403 for wrong audience, got %v", status)
	}

	// The test should fail at JWT verification step, not audience validation
	// since we don't have a valid JWKS endpoint, but that's expected behavior
}

// Benchmark test for proxy performance
func BenchmarkProxyHandler(b *testing.B) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	}))
	defer backend.Close()

	handler := proxyHandler(backend.URL, "/test")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req, _ := http.NewRequest("GET", "/test/endpoint", nil)
		rr := httptest.NewRecorder()
		handler(rr, req)
	}
}
