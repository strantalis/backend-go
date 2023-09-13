package tdf3

import (
	"encoding/json"
	"testing"
)

func TestDeserializing(t *testing.T) {
	serializedAttr := `{ "attribute": "https://the.authority.example.com/suborg/attr/the%2Fattribute/val/a%20value" }`
	var attr Attribute
	err := json.Unmarshal([]byte(serializedAttr), &attr)
	if err != nil {
		t.Fatalf("Error unmarshaling: %v", err)
	}

	if attr.Authority != "https://the.authority.example.com/suborg" {
		t.Fatalf("Got [%s] for authority, wanted [%s]", attr.Authority, "https://the.authority.example.com/suborg")
	}
	if attr.Name != "the/attribute" {
		t.Fatalf("Got [%s] for attribute name, wanted [the/attribute]", attr.Name)
	}
	if attr.Value != "a value" {
		t.Fatalf("Got [%s] for attribute value, wanted [a value]", attr.Value)
	}
}

func TestDeserializingInvalidAttributes(t *testing.T) {
	var attr Attribute
	err := json.Unmarshal([]byte(`{"attribute": "https://example.org" }`), &attr)
	if err == nil {
		t.Fatalf("Should have failed")
	}
}
