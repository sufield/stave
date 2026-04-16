package graph

import "testing"

func TestCypherValue_SingleQuoteEscaping(t *testing.T) {
	result := cypherValue("bucket-O'Brien")
	expected := "'bucket-O''Brien'"
	if result != expected {
		t.Errorf("cypherValue single quote: got %q, want %q\n"+
			"Cypher uses '' not \\' for single-quote escaping", result, expected)
	}
}

func TestCypherValue_MultipleSingleQuotes(t *testing.T) {
	result := cypherValue("it's O'Brien's bucket")
	expected := "'it''s O''Brien''s bucket'"
	if result != expected {
		t.Errorf("cypherValue multiple quotes: got %q, want %q", result, expected)
	}
}

func TestCypherValue_NoSingleQuote(t *testing.T) {
	result := cypherValue("arn:aws:s3:::normal-bucket")
	expected := "'arn:aws:s3:::normal-bucket'"
	if result != expected {
		t.Errorf("cypherValue no quotes: got %q, want %q", result, expected)
	}
}

func TestCypherValue_Bool(t *testing.T) {
	if cypherValue(true) != "true" {
		t.Error("true")
	}
	if cypherValue(false) != "false" {
		t.Error("false")
	}
}

func TestCypherValue_Int(t *testing.T) {
	if cypherValue(42) != "42" {
		t.Errorf("int: got %q", cypherValue(42))
	}
}
