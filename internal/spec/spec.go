// Package spec loads the parts of an OpenAPI 3 document that matter for a
// security review.
package spec

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Methods are the HTTP operations an OpenAPI path item can define.
var Methods = []string{"get", "put", "post", "delete", "options", "head", "patch", "trace"}

// Requirement is one security requirement object, e.g. {"bearerAuth": []}.
// An empty requirement ({}) means the operation may be called anonymously.
type Requirement map[string][]string

// SecurityScheme is a subset of the OpenAPI Security Scheme Object.
type SecurityScheme struct {
	Type   string `json:"type"`
	Scheme string `json:"scheme"`
	In     string `json:"in"`
	Name   string `json:"name"`
}

// Server is a subset of the OpenAPI Server Object.
type Server struct {
	URL string `json:"url"`
}

// Operation is a single method on a path.
type Operation struct {
	Method      string
	Path        string
	OperationID string
	Summary     string
	Deprecated  bool
	// Security is nil when the operation inherits the global requirements,
	// and an empty (non-nil) slice when it explicitly disables security.
	Security []Requirement
	Public   bool // marked with the x-public extension
}

// Key returns "METHOD /path".
func (o Operation) Key() string {
	return strings.ToUpper(o.Method) + " " + o.Path
}

// Document is a parsed OpenAPI 3 specification.
type Document struct {
	OpenAPI         string
	Title           string
	Servers         []Server
	Security        []Requirement
	SecuritySchemes map[string]SecurityScheme
	Operations      []Operation
}

type rawOperation struct {
	OperationID string         `json:"operationId"`
	Summary     string         `json:"summary"`
	Deprecated  bool           `json:"deprecated"`
	Security    *[]Requirement `json:"security"`
	Public      bool           `json:"x-public"`
}

type rawDocument struct {
	OpenAPI string `json:"openapi"`
	Swagger string `json:"swagger"`
	Info    struct {
		Title string `json:"title"`
	} `json:"info"`
	Servers    []Server                              `json:"servers"`
	Security   []Requirement                         `json:"security"`
	Paths      map[string]map[string]json.RawMessage `json:"paths"`
	Components struct {
		SecuritySchemes map[string]SecurityScheme `json:"securitySchemes"`
	} `json:"components"`
}

// Load reads a JSON OpenAPI document from disk.
func Load(path string) (*Document, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read spec: %w", err)
	}
	return Parse(raw)
}

// Parse decodes a JSON OpenAPI 3 document. Path-level keys that are not
// HTTP methods (parameters, summary, servers, …) are ignored.
func Parse(raw []byte) (*Document, error) {
	var doc rawDocument
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse spec: %w", err)
	}
	if doc.Swagger != "" {
		return nil, errors.New("Swagger 2.0 documents are not supported; convert to OpenAPI 3 first")
	}
	if !strings.HasPrefix(doc.OpenAPI, "3.") {
		return nil, fmt.Errorf("unsupported or missing openapi version %q (expected 3.x)", doc.OpenAPI)
	}

	out := &Document{
		OpenAPI:         doc.OpenAPI,
		Title:           doc.Info.Title,
		Servers:         doc.Servers,
		Security:        doc.Security,
		SecuritySchemes: doc.Components.SecuritySchemes,
	}

	paths := make([]string, 0, len(doc.Paths))
	for p := range doc.Paths {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, p := range paths {
		item := doc.Paths[p]
		for _, method := range Methods {
			body, ok := item[method]
			if !ok {
				continue
			}
			var op rawOperation
			if err := json.Unmarshal(body, &op); err != nil {
				return nil, fmt.Errorf("parse %s %s: %w", strings.ToUpper(method), p, err)
			}
			o := Operation{
				Method:      method,
				Path:        p,
				OperationID: op.OperationID,
				Summary:     op.Summary,
				Deprecated:  op.Deprecated,
				Public:      op.Public,
			}
			if op.Security != nil {
				o.Security = *op.Security
				if o.Security == nil {
					o.Security = []Requirement{}
				}
			}
			out.Operations = append(out.Operations, o)
		}
	}
	return out, nil
}

// EffectiveSecurity returns the requirements that apply to op, taking
// global defaults into account.
func (d *Document) EffectiveSecurity(op Operation) []Requirement {
	if op.Security != nil {
		return op.Security
	}
	return d.Security
}
