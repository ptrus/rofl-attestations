package worker

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/spruceid/siwe-go"
)

// AuthClient handles SIWE authentication and JWT token management.
type AuthClient struct {
	backendURL string
	privateKey *ecdsa.PrivateKey
	address    common.Address
	siweDomain string
	chainID    int
	logger     *slog.Logger

	mu    sync.RWMutex
	token string
	exp   time.Time
}

// NewAuthClient creates a new authentication client.
func NewAuthClient(backendURL, privateKeyHex, siweDomain string, chainID int, logger *slog.Logger) (*AuthClient, error) {
	// Parse private key
	privKeyBytes, err := hex.DecodeString(strings.TrimPrefix(privateKeyHex, "0x"))
	if err != nil {
		return nil, fmt.Errorf("failed to decode private key: %w", err)
	}

	privateKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	address := crypto.PubkeyToAddress(privateKey.PublicKey)

	return &AuthClient{
		backendURL: backendURL,
		privateKey: privateKey,
		address:    address,
		siweDomain: siweDomain,
		chainID:    chainID,
		logger:     logger,
	}, nil
}

// GetToken returns a valid JWT token, refreshing if necessary.
func (a *AuthClient) GetToken(ctx context.Context) (string, error) {
	a.mu.RLock()
	// Check if we have a valid token (with 5 min buffer)
	if a.token != "" && time.Now().Add(5*time.Minute).Before(a.exp) {
		token := a.token
		a.mu.RUnlock()
		return token, nil
	}
	a.mu.RUnlock()

	// Need to get a new token
	a.mu.Lock()
	defer a.mu.Unlock()

	// Double-check in case another goroutine already refreshed
	if a.token != "" && time.Now().Add(5*time.Minute).Before(a.exp) {
		return a.token, nil
	}

	// Perform SIWE login
	token, err := a.performSIWELogin(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to perform SIWE login: %w", err)
	}

	// Estimate expiry (12 hours is the default from backend)
	a.token = token
	a.exp = time.Now().Add(11 * time.Hour) // 11 hours to be safe

	a.logger.Info("obtained new JWT token", "address", a.address.Hex())

	return a.token, nil
}

// performSIWELogin executes the complete SIWE authentication flow.
func (a *AuthClient) performSIWELogin(ctx context.Context) (string, error) {
	// Step 1: Get nonce
	nonce, err := a.getNonce(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get nonce: %w", err)
	}

	// Step 2: Build SIWE message
	msg, err := siwe.InitMessage(
		a.siweDomain,
		a.address.Hex(),
		"http://"+a.siweDomain,
		nonce,
		map[string]interface{}{
			"chainId":   a.chainID,
			"version":   "1",
			"statement": "Sign in to ROFL App Backend",
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to build SIWE message: %w", err)
	}

	// Step 3: Sign the message
	msgHash := signHash([]byte(msg.String()))
	sig, err := crypto.Sign(msgHash.Bytes(), a.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	// Step 4: Authenticate with backend
	token, err := a.authenticate(ctx, msg.String(), sig)
	if err != nil {
		return "", fmt.Errorf("failed to authenticate: %w", err)
	}

	return token, nil
}

// getNonce requests a nonce from the backend.
func (a *AuthClient) getNonce(ctx context.Context) (string, error) {
	url := fmt.Sprintf("%s/auth/nonce?address=%s", a.backendURL, a.address.Hex())
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Nonce string `json:"nonce"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Nonce, nil
}

// authenticate sends the signed SIWE message to the backend and receives a JWT token.
func (a *AuthClient) authenticate(ctx context.Context, message string, signature []byte) (string, error) {
	// Prepare request body
	payload := map[string]string{
		"message": message,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Add signature as query parameter
	sigHex := "0x" + hex.EncodeToString(signature)
	url := fmt.Sprintf("%s/auth/login?sig=%s", a.backendURL, sigHex)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send request: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("authentication failed with status code: %d", resp.StatusCode)
	}

	var result struct {
		Token   string `json:"token"`
		Address string `json:"address"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	if result.Token == "" {
		return "", fmt.Errorf("empty token in response")
	}

	if !strings.EqualFold(result.Address, a.address.Hex()) {
		return "", fmt.Errorf("address mismatch: expected %s, got %s", a.address.Hex(), result.Address)
	}

	return result.Token, nil
}

// signHash creates an EIP-191 prefixed message hash for signing.
func signHash(data []byte) common.Hash {
	msg := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(data), data)
	return crypto.Keccak256Hash([]byte(msg))
}
