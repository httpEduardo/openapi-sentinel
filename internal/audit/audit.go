// Package audit applies security rules to a parsed OpenAPI document.
package audit

import (
	"fmt"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/httpEduardo/openapi-sentinel/internal/spec"
)

// Severity ranks findings.
type Severity int

const (
	Low Severity = iota + 1
	Medium
	High
	Critical
)

var severityNames = map[Severity]string{Low: "low", Medium: "medium", High: "high", Critical: "critical"}

func (s Severity) String() string {
	if n, ok := severityNames[s]; ok {
		return n
	}
	return "unknown"
}

// MarshalText renders severities as strings in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity converts "high" into High.
func ParseSeverity(name string) (Severity, error) {
	for s, n := range severityNames {
		if strings.EqualFold(n, strings.TrimSpace(name)) {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown severity %q (want low, medium, high or critical)", name)
}

// Finding is one issue in the document.
type Finding struct {
	RuleID    string   `json:"rule_id"`
	Severity  Severity `json:"severity"`
	Operation string   `json:"operation,omitempty"`
	Message   string   `json:"message"`
}

// Options controls which operations are expected to be public.
type Options struct {
	// Public lists "METHOD /path" patterns (path globs allowed, e.g.
	// "GET /docs/*") for endpoints that are intentionally unauthenticated.
	Public []string
}

var privilegedPath = regexp.MustCompile(`(?i)(^|/)(admin|internal|manage(ment)?|debug|actuator|config|system)(/|$)`)

// Run audits the document and returns findings sorted by severity.
func Run(doc *spec.Document, opts Options) ([]Finding, error) {
	public, err := compilePublic(opts.Public)
	if err != nil {
		return nil, err
	}

	var out []Finding
	out = append(out, checkDocument(doc)...)
	for _, op := range doc.Operations {
		out = append(out, checkOperation(doc, op, public)...)
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].Operation != out[j].Operation {
			return out[i].Operation < out[j].Operation
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out, nil
}

type publicPattern struct {
	method string // "" or "*" matches any method
	glob   string
}

func compilePublic(patterns []string) ([]publicPattern, error) {
	var out []publicPattern
	for _, raw := range patterns {
		fields := strings.Fields(raw)
		var p publicPattern
		switch len(fields) {
		case 1:
			p = publicPattern{glob: fields[0]}
		case 2:
			p = publicPattern{method: strings.ToLower(fields[0]), glob: fields[1]}
		default:
			return nil, fmt.Errorf("invalid public pattern %q (want \"METHOD /path\" or \"/path\")", raw)
		}
		if _, err := path.Match(p.glob, "/"); err != nil {
			return nil, fmt.Errorf("invalid public pattern %q: %w", raw, err)
		}
		out = append(out, p)
	}
	return out, nil
}

func isPublic(op spec.Operation, patterns []publicPattern) bool {
	if op.Public {
		return true
	}
	for _, p := range patterns {
		if p.method != "" && p.method != "*" && p.method != op.Method {
			continue
		}
		if ok, _ := path.Match(p.glob, op.Path); ok {
			return true
		}
	}
	return false
}

func checkDocument(doc *spec.Document) []Finding {
	var out []Finding

	if len(doc.Security) == 0 {
		out = append(out, Finding{
			RuleID: "OAS007", Severity: Low,
			Message: "no global security requirement; every operation has to declare its own, which is easy to forget",
		})
	}

	names := make([]string, 0, len(doc.SecuritySchemes))
	for name := range doc.SecuritySchemes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		s := doc.SecuritySchemes[name]
		switch {
		case strings.EqualFold(s.Type, "apiKey") && strings.EqualFold(s.In, "query"):
			out = append(out, Finding{
				RuleID: "OAS004", Severity: Medium,
				Message: fmt.Sprintf("security scheme %q sends the API key in the query string, where it ends up in logs and browser history", name),
			})
		case strings.EqualFold(s.Type, "http") && strings.EqualFold(s.Scheme, "basic"):
			out = append(out, Finding{
				RuleID: "OAS006", Severity: Low,
				Message: fmt.Sprintf("security scheme %q uses HTTP Basic; prefer tokens that can be scoped and revoked", name),
			})
		}
	}

	for _, s := range doc.Servers {
		u, err := url.Parse(s.URL)
		if err != nil || u.Scheme != "http" {
			continue
		}
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			continue
		}
		out = append(out, Finding{
			RuleID: "OAS005", Severity: Medium,
			Message: fmt.Sprintf("server %s is served over plain HTTP", s.URL),
		})
	}
	return out
}

func checkOperation(doc *spec.Document, op spec.Operation, public []publicPattern) []Finding {
	var out []Finding
	key := op.Key()
	reqs := doc.EffectiveSecurity(op)

	anonymous := len(reqs) == 0
	optional := false
	for _, r := range reqs {
		if len(r) == 0 {
			optional = true
		}
		for name := range r {
			if _, ok := doc.SecuritySchemes[name]; !ok {
				out = append(out, Finding{
					RuleID: "OAS003", Severity: High, Operation: key,
					Message: fmt.Sprintf("references security scheme %q, which is not defined in components.securitySchemes", name),
				})
			}
		}
	}

	privileged := privilegedPath.MatchString(op.Path)
	if !isPublic(op, public) {
		switch {
		case anonymous:
			sev := High
			reason := "has no security requirement"
			if op.Security != nil {
				reason = "explicitly disables security (security: [])"
			}
			if privileged || op.Method == "delete" {
				sev = Critical
			}
			out = append(out, Finding{RuleID: "OAS001", Severity: sev, Operation: key, Message: reason})
		case optional:
			sev := Medium
			if privileged || op.Method == "delete" {
				sev = High
			}
			out = append(out, Finding{
				RuleID: "OAS002", Severity: sev, Operation: key,
				Message: "authentication is optional (an empty {} requirement allows anonymous access)",
			})
		}
	}

	if op.Deprecated {
		out = append(out, Finding{
			RuleID: "OAS008", Severity: Low, Operation: key,
			Message: "is deprecated but still published; confirm it is still maintained or schedule its removal",
		})
	}
	return out
}

// Worst returns the highest severity present, or 0.
func Worst(findings []Finding) Severity {
	var w Severity
	for _, f := range findings {
		if f.Severity > w {
			w = f.Severity
		}
	}
	return w
}
