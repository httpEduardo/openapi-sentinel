package main

import (
    "encoding/json"
    "flag"
    "fmt"
    "os"
    "strings"
)

type Spec struct {
    OpenAPI  string                 `json:"openapi"`
    Info     map[string]interface{} `json:"info"`
    Security []map[string][]string  `json:"security"`
    Paths    map[string]PathItem    `json:"paths"`
}

type PathItem map[string]Operation

type Operation struct {
    Summary  string                   `json:"summary"`
    Security []map[string][]string    `json:"security"`
    Deprecated bool                   `json:"deprecated"`
}

func readSpec(path string) (Spec, error) {
    raw, err := os.ReadFile(path)
    if err != nil {
        return Spec{}, err
    }
    var spec Spec
    if err := json.Unmarshal(raw, &spec); err != nil {
        return Spec{}, err
    }
    return spec, nil
}

func hasSecurity(global []map[string][]string, op Operation) bool {
    if op.Security != nil {
        return len(op.Security) > 0
    }
    return len(global) > 0
}

func main() {
    input := flag.String("input", "spec.json", "OpenAPI spec JSON")
    flag.Parse()

    spec, err := readSpec(*input)
    if err != nil {
        fmt.Println("Failed to read spec:", err)
        os.Exit(1)
    }

    missing := 0
    reviewed := 0

    for path, item := range spec.Paths {
        for method, op := range item {
            reviewed += 1
            needsReview := []string{}
            if !hasSecurity(spec.Security, op) {
                needsReview = append(needsReview, "no security")
                missing += 1
            }
            if strings.Contains(path, "admin") {
                needsReview = append(needsReview, "admin path")
            }
            if method == "delete" || method == "post" || method == "put" {
                needsReview = append(needsReview, "destructive")
            }
            if op.Deprecated {
                needsReview = append(needsReview, "deprecated")
            }

            if len(needsReview) > 0 {
                fmt.Printf("%s %s -> %s\n", strings.ToUpper(method), path, strings.Join(needsReview, ", "))
            }
        }
    }

    fmt.Printf("\nEndpoints reviewed: %d\n", reviewed)
    fmt.Printf("Endpoints missing security: %d\n", missing)
}
