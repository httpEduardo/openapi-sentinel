package spec

import "testing"

func TestParseIgnoresNonMethodKeys(t *testing.T) {
	doc, err := Parse([]byte(`{
		"openapi": "3.0.0",
		"paths": {"/items/{id}": {
			"summary": "Items",
			"parameters": [{"name": "id", "in": "path"}],
			"get": {"summary": "read"}
		}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Operations) != 1 || doc.Operations[0].Key() != "GET /items/{id}" {
		t.Fatalf("unexpected operations: %+v", doc.Operations)
	}
}

func TestSecurityInheritance(t *testing.T) {
	doc, err := Parse([]byte(`{
		"openapi": "3.0.0",
		"security": [{"bearer": []}],
		"paths": {"/a": {
			"get": {},
			"post": {"security": []},
			"put": {"security": null}
		}}
	}`))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, op := range doc.Operations {
		got[op.Method] = len(doc.EffectiveSecurity(op))
	}
	if got["get"] != 1 || got["post"] != 0 || got["put"] != 1 {
		t.Fatalf("unexpected effective security: %v", got)
	}
}

func TestRejectsUnsupportedVersions(t *testing.T) {
	for _, body := range []string{`{"swagger": "2.0"}`, `{"openapi": "4.0"}`, `{}`} {
		if _, err := Parse([]byte(body)); err == nil {
			t.Errorf("expected an error for %s", body)
		}
	}
}

func TestOperationsAreSorted(t *testing.T) {
	doc, err := Parse([]byte(`{"openapi":"3.0.0","paths":{"/b":{"post":{},"get":{}},"/a":{"delete":{}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, op := range doc.Operations {
		keys = append(keys, op.Key())
	}
	want := []string{"DELETE /a", "GET /b", "POST /b"}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("got %v, want %v", keys, want)
		}
	}
}
