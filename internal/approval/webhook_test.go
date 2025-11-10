package approval

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/davidcohan/port-authorizing/internal/config"
)

func TestNewWebhookProvider(t *testing.T) {
	urlSource := config.ConfigSource{Type: config.ConfigSourceTypePlain, Value: "https://example.com/webhook"}
	provider := NewWebhookProvider(urlSource, nil)

	if provider == nil {
		t.Fatal("NewWebhookProvider returned nil")
	}

	if provider.GetProviderName() != "webhook" {
		t.Errorf("GetProviderName() = %v, want webhook", provider.GetProviderName())
	}

	// Verify URL source is stored correctly
	if provider.urlSource.Value != "https://example.com/webhook" {
		t.Errorf("urlSource.Value = %v, want https://example.com/webhook", provider.urlSource.Value)
	}
}

func TestWebhookProvider_SendApprovalRequest(t *testing.T) {
	// Create test HTTP server
	var receivedPayload webhookPayload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}

		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Decode payload
		if err := json.NewDecoder(r.Body).Decode(&receivedPayload); err != nil {
			t.Errorf("Failed to decode payload: %v", err)
		}

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider := NewWebhookProvider(config.ConfigSource{Type: config.ConfigSourceTypePlain, Value: server.URL}, nil)

	req := &Request{
		ID:           "test-123",
		Username:     "alice",
		ConnectionID: "conn-456",
		Method:       "DELETE",
		Path:         "/api/users/1",
		RequestedAt:  time.Now(),
		Metadata: map[string]string{
			"test": "value",
		},
	}

	ctx := context.Background()
	err := provider.SendApprovalRequest(ctx, req)

	if err != nil {
		t.Fatalf("SendApprovalRequest() error = %v", err)
	}

	// Verify payload
	if receivedPayload.RequestID != "test-123" {
		t.Errorf("RequestID = %v, want test-123", receivedPayload.RequestID)
	}

	if receivedPayload.Username != "alice" {
		t.Errorf("Username = %v, want alice", receivedPayload.Username)
	}

	if receivedPayload.Method != "DELETE" {
		t.Errorf("Method = %v, want DELETE", receivedPayload.Method)
	}
}

func TestWebhookProvider_SendApprovalRequest_Error(t *testing.T) {
	// Create server that returns error
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	provider := NewWebhookProvider(config.ConfigSource{Type: config.ConfigSourceTypePlain, Value: server.URL}, nil)

	req := &Request{
		ID:       "test-123",
		Username: "alice",
		Method:   "DELETE",
		Path:     "/api/users/1",
	}

	ctx := context.Background()
	err := provider.SendApprovalRequest(ctx, req)

	if err == nil {
		t.Error("SendApprovalRequest() expected error, got nil")
	}
}

func TestWebhookProvider_SendApprovalRequest_InvalidURL(t *testing.T) {
	urlSource := config.ConfigSource{Type: config.ConfigSourceTypePlain, Value: "http://invalid-host-that-does-not-exist-12345"}
	provider := NewWebhookProvider(urlSource, nil)

	req := &Request{
		ID:       "test-123",
		Username: "alice",
		Method:   "DELETE",
		Path:     "/api/users/1",
	}

	ctx := context.Background()
	err := provider.SendApprovalRequest(ctx, req)

	if err == nil {
		t.Error("SendApprovalRequest() expected error for invalid URL, got nil")
	}
}

func BenchmarkWebhookProvider_SendApprovalRequest(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	provider := NewWebhookProvider(config.ConfigSource{Type: config.ConfigSourceTypePlain, Value: server.URL}, nil)
	req := &Request{
		ID:       "test-123",
		Username: "alice",
		Method:   "DELETE",
		Path:     "/api/users/1",
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = provider.SendApprovalRequest(ctx, req)
	}
}
