package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

type Config struct {
	WellKnownURL string
	ClientID     string
	GandalfURL   string
	STSURL       string
	ArenaURL     string
	CICSURL      string
	HTTPProxy    string
	HTTPSProxy   string
	NoProxy      string
}

type JWTClaims struct {
	Sub     string `json:"sub"`
	Aud     string `json:"aud"`
	AzpName string `json:"azp_name"`
	jwt.RegisteredClaims
}

type JWKSet struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X5t string `json:"x5t"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type OIDCConfig struct {
	JWKSUri string `json:"jwks_uri"`
}

var jwkCache map[string]*rsa.PublicKey
var lastJWKFetch time.Time

func main() {
	router := setupRouter()
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", router))
}

func setupRouter() *mux.Router {
	config := loadConfig()
	jwkCache = make(map[string]*rsa.PublicKey)

	r := mux.NewRouter()

	// Apply JWT middleware to all routes except health check
	protected := r.PathPrefix("/").Subrouter()
	protected.Use(jwtMiddleware(config))

	// Health check endpoint (no auth required)
	r.HandleFunc("/", healthCheck).Methods("GET")

	// Protected proxy endpoints
	protected.PathPrefix("/gandalf/").HandlerFunc(proxyHandler(config.GandalfURL, "/gandalf"))
	protected.PathPrefix("/sts/").HandlerFunc(proxyHandler(config.STSURL, "/sts"))
	protected.PathPrefix("/arena/").HandlerFunc(proxyHandler(config.ArenaURL, "/arena"))
	protected.PathPrefix("/cics/").HandlerFunc(proxyHandler(config.CICSURL, "/cics"))

	return r
}

func loadConfig() *Config {
	return &Config{
		WellKnownURL: os.Getenv("AZURE_APP_WELL_KNOWN_URL"),
		ClientID:     os.Getenv("AZURE_APP_CLIENT_ID"),
		GandalfURL:   os.Getenv("GANDALF_BASE_URL"),
		STSURL:       os.Getenv("STS_BASE_URL"),
		ArenaURL:     os.Getenv("ARENA_BASE_URL"),
		CICSURL:      os.Getenv("CICS_BASE_URL"),
		HTTPProxy:    os.Getenv("HTTP_PROXY"),
		HTTPSProxy:   os.Getenv("HTTPS_PROXY"),
		NoProxy:      os.Getenv("NO_PROXY"),
	}
}

func healthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(""))
}

func jwtMiddleware(config *Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := r.Header.Get("X-Proxy-Authorization")
			if token == "" {
				http.Error(w, "no access_token provided", http.StatusForbidden)
				return
			}

			// Remove "Bearer " prefix if present
			token = strings.TrimPrefix(token, "Bearer ")

			claims, err := verifyJWT(token, config)
			if err != nil {
				log.Printf("JWT verification failed: %v", err)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}

			if claims.Aud != config.ClientID {
				log.Printf("Token has wrong aud: %s, expected: %s", claims.Aud, config.ClientID)
				http.Error(w, fmt.Sprintf("token has wrong aud %s", claims.Aud), http.StatusForbidden)
				return
			}

			// Set headers like the Lua script does
			r.Header.Set("X-Azure-Client-Id", claims.Sub)
			r.Header.Set("X-Azure-Azp-Name", claims.AzpName)
			r.Header.Del("Proxy-Authorization") // Remove auth header like nginx config

			log.Printf("tilkobling fra %s", claims.Sub)
			next.ServeHTTP(w, r)
		})
	}
}

func verifyJWT(tokenString string, config *Config) (*JWTClaims, error) {
	// Parse token to get the key ID
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid header not found")
		}

		// Get public key for this kid
		publicKey, err := getPublicKey(kid, config)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %v", err)
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, fmt.Errorf("failed to parse claims")
	}

	return claims, nil
}

func getPublicKey(kid string, config *Config) (*rsa.PublicKey, error) {
	// Check cache first (refresh every 24 hours)
	if publicKey, exists := jwkCache[kid]; exists && time.Since(lastJWKFetch) < 24*time.Hour {
		return publicKey, nil
	}

	// Fetch OIDC configuration
	oidcConfig, err := fetchOIDCConfig(config.WellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC config: %v", err)
	}

	// Fetch JWK set
	jwkSet, err := fetchJWKSet(oidcConfig.JWKSUri)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWK set: %v", err)
	}

	// Find the key with matching kid
	for _, jwk := range jwkSet.Keys {
		if jwk.Kid == kid && jwk.Kty == "RSA" {
			publicKey, err := jwkToRSAPublicKey(jwk)
			if err != nil {
				return nil, fmt.Errorf("failed to convert JWK to RSA public key: %v", err)
			}

			// Cache the key
			jwkCache[kid] = publicKey
			lastJWKFetch = time.Now()

			return publicKey, nil
		}
	}

	return nil, fmt.Errorf("key with kid %s not found", kid)
}

func fetchOIDCConfig(wellKnownURL string) (*OIDCConfig, error) {
	client := createHTTPClient()
	resp, err := client.Get(wellKnownURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var config OIDCConfig
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return &config, nil
}

func fetchJWKSet(jwksURI string) (*JWKSet, error) {
	client := createHTTPClient()
	resp, err := client.Get(jwksURI)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwkSet JWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwkSet); err != nil {
		return nil, err
	}

	return &jwkSet, nil
}

func createHTTPClient() *http.Client {
	// Configure proxy settings if needed
	transport := &http.Transport{}

	if httpProxy := os.Getenv("HTTP_PROXY"); httpProxy != "" {
		if proxyURL, err := url.Parse(httpProxy); err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func jwkToRSAPublicKey(jwk JWK) (*rsa.PublicKey, error) {
	// Decode the modulus
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, err
	}

	// Decode the exponent
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, err
	}

	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := 0
	for _, b := range eBytes {
		e = e*256 + int(b)
	}

	return &rsa.PublicKey{
		N: n,
		E: e,
	}, nil
}

func proxyHandler(targetURL, prefix string) http.HandlerFunc {
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("Failed to parse target URL %s: %v", targetURL, err)
	}

	proxy := httputil.NewSingleHostReverseProxy(target)

	// Customize the director to handle path rewriting
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)

		// Rewrite path: remove the prefix (like nginx rewrite)
		// e.g., /gandalf/something -> /something
		if strings.HasPrefix(req.URL.Path, prefix+"/") {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, prefix)
		}

		// Set the target host
		req.Host = target.Host
		req.URL.Host = target.Host
		req.URL.Scheme = target.Scheme
	}

	// Handle proxy errors
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error for %s: %v", r.URL.Path, err)
		http.Error(w, "Bad Gateway", http.StatusBadGateway)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Proxying request to %s: %s %s", targetURL, r.Method, r.URL.Path)
		proxy.ServeHTTP(w, r)
	}
}
