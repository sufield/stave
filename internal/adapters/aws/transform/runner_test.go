package transform

import (
	"encoding/json"
	"testing"
)

// Confirms gojq (the new production dependency) compiles and runs a filter that
// reshapes a raw `aws iam list-roles`-style document into obs.v0.1 asset objects
// {id,type,vendor,properties} — the shape Iteration 1's filters emit.
func TestRunJQ_ReshapesRolesToAssets(t *testing.T) {
	var input any
	if err := json.Unmarshal([]byte(`{"Roles":[
		{"Arn":"arn:aws:iam::1:role/a","RoleName":"a"},
		{"Arn":"arn:aws:iam::1:role/b","RoleName":"b"}
	]}`), &input); err != nil {
		t.Fatal(err)
	}

	filter := `.Roles[] | {id:.Arn, type:"aws_iam_role", vendor:"aws", properties:{identity:{name:.RoleName}}}`
	out, err := runJQ(filter, input)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 {
		t.Fatalf("want 2 assets, got %d", len(out))
	}

	var a struct {
		ID, Type, Vendor string
	}
	if err := json.Unmarshal(out[0], &a); err != nil {
		t.Fatal(err)
	}
	if a.ID != "arn:aws:iam::1:role/a" || a.Type != "aws_iam_role" || a.Vendor != "aws" {
		t.Errorf("unexpected asset: %s", out[0])
	}
}

// A jq runtime error must surface, not silently drop the asset (fail loud).
func TestRunJQ_RuntimeErrorSurfaces(t *testing.T) {
	if _, err := runJQ(`.foo + 1`, map[string]any{"foo": "a-string"}); err == nil {
		t.Fatal("want type error adding string and number, got nil")
	}
}
