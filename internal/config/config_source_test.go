package config

import (
	"encoding/json"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConfigSource_MarshalYAML_PlainValue(t *testing.T) {
	cs := ConfigSource{
		Type:  ConfigSourceTypePlain,
		Value: "my-password",
	}

	data, err := yaml.Marshal(cs)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Plain values should marshal as simple strings
	expected := "my-password\n"
	if string(data) != expected {
		t.Errorf("Expected %q, got %q", expected, string(data))
	}
}

func TestConfigSource_MarshalYAML_SecretType(t *testing.T) {
	cs := ConfigSource{
		Type:    ConfigSourceTypeSecret,
		Value:   "resolved-secret-value", // This should NOT be persisted
		Ref:     "my-secret",
		RefName: "password",
	}

	data, err := yaml.Marshal(cs)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal to check structure
	var result map[string]interface{}
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Type should be preserved
	if result["type"] != "secret" {
		t.Errorf("Expected type='secret', got %v", result["type"])
	}

	// Ref should be preserved
	if result["ref"] != "my-secret" {
		t.Errorf("Expected ref='my-secret', got %v", result["ref"])
	}

	// RefName should be preserved
	if result["ref_name"] != "password" {
		t.Errorf("Expected ref_name='password', got %v", result["ref_name"])
	}

	// Value should be empty (not persisted for secrets)
	if result["value"] != "" && result["value"] != nil {
		t.Errorf("Expected value to be empty for secret type, got %v", result["value"])
	}
}

func TestConfigSource_MarshalYAML_ConfigMapType(t *testing.T) {
	cs := ConfigSource{
		Type:    ConfigSourceTypeConfigMap,
		Value:   "resolved-configmap-value", // This should NOT be persisted
		Ref:     "my-configmap",
		RefName: "database-url",
	}

	data, err := yaml.Marshal(cs)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal to check structure
	var result map[string]interface{}
	if err := yaml.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Type should be preserved
	if result["type"] != "configmap" {
		t.Errorf("Expected type='configmap', got %v", result["type"])
	}

	// Value should be empty (not persisted for configmaps)
	if result["value"] != "" && result["value"] != nil {
		t.Errorf("Expected value to be empty for configmap type, got %v", result["value"])
	}
}

func TestConfigSource_MarshalJSON(t *testing.T) {
	cs := ConfigSource{
		Type:    ConfigSourceTypeSecret,
		Value:   "resolved-secret",
		Ref:     "my-secret",
		RefName: "password",
	}

	data, err := json.Marshal(cs)
	if err != nil {
		t.Fatalf("Failed to marshal JSON: %v", err)
	}

	// Unmarshal to check structure
	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	// All fields should be present in JSON (for API communication)
	if result["type"] != "secret" {
		t.Errorf("Expected type='secret', got %v", result["type"])
	}
	if result["ref"] != "my-secret" {
		t.Errorf("Expected ref='my-secret', got %v", result["ref"])
	}
	if result["ref_name"] != "password" {
		t.Errorf("Expected ref_name='password', got %v", result["ref_name"])
	}
}

func TestConfigSource_UnmarshalYAML_PlainString(t *testing.T) {
	data := []byte("my-password")

	var cs ConfigSource
	if err := yaml.Unmarshal(data, &cs); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if cs.Type != ConfigSourceTypePlain {
		t.Errorf("Expected type='plain', got %v", cs.Type)
	}
	if cs.Value != "my-password" {
		t.Errorf("Expected value='my-password', got %v", cs.Value)
	}
}

func TestConfigSource_UnmarshalYAML_SecretObject(t *testing.T) {
	data := []byte(`
type: secret
ref: my-secret
ref_name: password
`)

	var cs ConfigSource
	if err := yaml.Unmarshal(data, &cs); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	if cs.Type != ConfigSourceTypeSecret {
		t.Errorf("Expected type='secret', got %v", cs.Type)
	}
	if cs.Ref != "my-secret" {
		t.Errorf("Expected ref='my-secret', got %v", cs.Ref)
	}
	if cs.RefName != "password" {
		t.Errorf("Expected ref_name='password', got %v", cs.RefName)
	}
}

func TestConfigSource_RoundTrip_Secret(t *testing.T) {
	// Simulate what happens when a secret is loaded, resolved, and saved
	original := ConfigSource{
		Type:    ConfigSourceTypeSecret,
		Ref:     "my-secret",
		RefName: "password",
	}

	// After resolution, Value is populated
	resolved := original
	resolved.Value = "super-secret-password"

	// Marshal (simulating save)
	data, err := yaml.Marshal(resolved)
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Unmarshal (simulating load)
	var loaded ConfigSource
	if err := yaml.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// After round-trip, the resolved value should NOT be persisted
	if loaded.Value != "" {
		t.Errorf("Expected value to be empty after round-trip, got %v", loaded.Value)
	}
	if loaded.Type != ConfigSourceTypeSecret {
		t.Errorf("Expected type='secret', got %v", loaded.Type)
	}
	if loaded.Ref != "my-secret" {
		t.Errorf("Expected ref='my-secret', got %v", loaded.Ref)
	}
}

func TestConfigSource_UnmarshalJSON_String(t *testing.T) {
	data := []byte(`"my-password"`)

	var cs ConfigSource
	if err := json.Unmarshal(data, &cs); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if cs.Type != ConfigSourceTypePlain {
		t.Errorf("Expected type='plain', got %v", cs.Type)
	}
	if cs.Value != "my-password" {
		t.Errorf("Expected value='my-password', got %v", cs.Value)
	}
}

func TestConfigSource_UnmarshalJSON_Object(t *testing.T) {
	data := []byte(`{"type":"secret","ref":"my-secret","ref_name":"password"}`)

	var cs ConfigSource
	if err := json.Unmarshal(data, &cs); err != nil {
		t.Fatalf("Failed to unmarshal JSON: %v", err)
	}

	if cs.Type != ConfigSourceTypeSecret {
		t.Errorf("Expected type='secret', got %v", cs.Type)
	}
	if cs.Ref != "my-secret" {
		t.Errorf("Expected ref='my-secret', got %v", cs.Ref)
	}
	if cs.RefName != "password" {
		t.Errorf("Expected ref_name='password', got %v", cs.RefName)
	}
}

