package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"secure spec", []string{"-input", "../../examples/secure-api.json"}, exitOK},
		{"demo spec", []string{"-input", "../../examples/demo-api.json"}, exitFindings},
		{"demo spec, critical only", []string{"-input", "../../examples/demo-api.json", "-fail-on", "critical", "-public", "/admin/*"}, exitOK},
		{"missing file", []string{"-input", "nope.json"}, exitUsage},
		{"bad format", []string{"-input", "../../examples/secure-api.json", "-format", "xml"}, exitUsage},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out, errOut bytes.Buffer
			if got := run(tt.args, &out, &errOut); got != tt.want {
				t.Fatalf("exit %d, want %d; stderr: %s", got, tt.want, errOut.String())
			}
		})
	}
}

func TestJSONOutput(t *testing.T) {
	var out, errOut bytes.Buffer
	run([]string{"-input", "../../examples/demo-api.json", "-format", "json"}, &out, &errOut)
	var got struct {
		Operations int `json:"operations"`
		Findings   []struct {
			RuleID   string `json:"rule_id"`
			Severity string `json:"severity"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if got.Operations != 7 || len(got.Findings) == 0 || got.Findings[0].Severity != "critical" {
		t.Fatalf("unexpected report: %+v", got)
	}
}
