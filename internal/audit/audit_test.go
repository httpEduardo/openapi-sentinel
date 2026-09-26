package audit

import (
	"testing"

	"github.com/httpEduardo/openapi-sentinel/internal/spec"
)

func mustParse(t *testing.T, body string) *spec.Document {
	t.Helper()
	doc, err := spec.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func find(findings []Finding, rule, op string) *Finding {
	for i := range findings {
		if findings[i].RuleID == rule && findings[i].Operation == op {
			return &findings[i]
		}
	}
	return nil
}

const schemes = `"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer"}}}`

func TestUnauthenticatedOperations(t *testing.T) {
	doc := mustParse(t, `{"openapi":"3.0.0",`+schemes+`,"paths":{
		"/reports":{"get":{}},
		"/admin/users":{"get":{}},
		"/items/{id}":{"delete":{}}
	}}`)
	findings, err := Run(doc, Options{})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]Severity{"GET /reports": High, "GET /admin/users": Critical, "DELETE /items/{id}": Critical}
	for op, want := range cases {
		f := find(findings, "OAS001", op)
		if f == nil || f.Severity != want {
			t.Errorf("%s: got %+v, want OAS001 %v", op, f, want)
		}
	}
}

func TestPublicEndpointsAreSkipped(t *testing.T) {
	doc := mustParse(t, `{"openapi":"3.0.0","security":[{"bearer":[]}],`+schemes+`,"paths":{
		"/health":{"get":{"security":[]}},
		"/docs/index":{"get":{"security":[]}},
		"/status":{"get":{"security":[],"x-public":true}}
	}}`)
	findings, err := Run(doc, Options{Public: []string{"GET /health", "/docs/*"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected no findings, got %+v", findings)
	}
}

func TestOptionalAuthentication(t *testing.T) {
	doc := mustParse(t, `{"openapi":"3.0.0",`+schemes+`,"security":[{"bearer":[]}],"paths":{
		"/feed":{"get":{"security":[{"bearer":[]},{}]}}
	}}`)
	findings, _ := Run(doc, Options{})
	if f := find(findings, "OAS002", "GET /feed"); f == nil || f.Severity != Medium {
		t.Fatalf("expected OAS002 medium, got %+v", findings)
	}
}

func TestUndefinedSchemeAndDocumentChecks(t *testing.T) {
	doc := mustParse(t, `{"openapi":"3.0.0",
		"servers":[{"url":"http://api.example.com"},{"url":"http://localhost:8080"}],
		"components":{"securitySchemes":{"key":{"type":"apiKey","in":"query","name":"k"}}},
		"paths":{"/a":{"get":{"security":[{"missing":[]}]}}}}`)
	findings, _ := Run(doc, Options{})
	for _, rule := range []string{"OAS003", "OAS004", "OAS005", "OAS007"} {
		found := false
		for _, f := range findings {
			if f.RuleID == rule {
				found = true
			}
		}
		if !found {
			t.Errorf("expected %s in %+v", rule, findings)
		}
	}
	count := 0
	for _, f := range findings {
		if f.RuleID == "OAS005" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("localhost should not be flagged; got %d OAS005 findings", count)
	}
}

func TestInvalidPublicPattern(t *testing.T) {
	doc := mustParse(t, `{"openapi":"3.0.0","paths":{}}`)
	if _, err := Run(doc, Options{Public: []string{"GET /a extra"}}); err == nil {
		t.Fatal("expected an error")
	}
}
