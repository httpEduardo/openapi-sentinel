# openapi-sentinel

Reviews an OpenAPI 3 specification and flags endpoints that anyone on the internet can call — plus a handful of related mistakes that tend to slip through API design reviews.

Broken authentication and authorization sit at the top of the [OWASP API Security Top 10](https://owasp.org/API-Security/) year after year, and a surprising number of them are visible in the spec before a single line of code runs: an admin route with `security: []` left over from local testing, an optional `{}` requirement nobody noticed, a scheme name with a typo that silently resolves to nothing. openapi-sentinel reads the spec and points those out, so the conversation happens in the pull request instead of after the incident.

## What it checks

| Rule | Severity | Description |
|------|----------|-------------|
| `OAS001` | High / Critical | Operation has no effective security requirement. Critical for admin/internal paths and `DELETE`. |
| `OAS002` | Medium / High | Security is optional — an empty `{}` requirement lets anonymous callers through. |
| `OAS003` | High | Operation references a security scheme that isn't defined in `components.securitySchemes`. |
| `OAS004` | Medium | API key sent in the query string (leaks into logs, proxies and browser history). |
| `OAS005` | Medium | Server URL uses plain `http://` (localhost is ignored). |
| `OAS006` | Low | HTTP Basic authentication scheme. |
| `OAS007` | Low | No global security requirement, so every operation must remember to declare one. |
| `OAS008` | Low | Deprecated operation still published. |

Security inheritance follows the spec: an operation without a `security` field uses the global requirements, while `security: []` explicitly opts out. Path-level keys like `parameters` and `summary` are handled correctly.

## Installation

Requires Go 1.21 or newer.

```bash
go install github.com/httpEduardo/openapi-sentinel/cmd/openapi-sentinel@latest
```

Or from a clone:

```bash
git clone https://github.com/httpEduardo/openapi-sentinel.git
cd openapi-sentinel
make build   # ./bin/openapi-sentinel
```

## Usage

```bash
openapi-sentinel -input examples/demo-api.json
```

```text
Demo API (OpenAPI 3.0.3): 7 operations reviewed

  [OAS001] CRITICAL GET /admin/users explicitly disables security (security: [])
  [OAS001] HIGH     POST /sessions explicitly disables security (security: [])
  [OAS003] HIGH     PUT /reports/{id} references security scheme "oauth2", which is not defined in components.securitySchemes
  [OAS004] MEDIUM   security scheme "legacyKey" sends the API key in the query string, where it ends up in logs and browser history
  [OAS005] MEDIUM   server http://api.example.com/v1 is served over plain HTTP
  [OAS002] MEDIUM   GET /reports/{id} authentication is optional (an empty {} requirement allows anonymous access)
  [OAS008] LOW      GET /v1/export is deprecated but still published; confirm it is still maintained or schedule its removal

Summary: 1 critical, 2 high, 3 medium, 1 low
```

### Declaring intentionally public endpoints

Some endpoints are meant to be open — health checks, login, docs. There are two ways to tell the tool:

**In the spec**, with a vendor extension on the operation:

```json
"/health": {
  "get": { "summary": "Health check", "security": [], "x-public": true }
}
```

**On the command line**, with `-public` (repeatable). Paths accept globs:

```bash
openapi-sentinel -input openapi.json -public "POST /sessions" -public "GET /docs/*"
```

The extension is usually the better choice: it documents intent next to the endpoint and shows up in code review when someone adds it.

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-input` | `openapi.json` | Path to the OpenAPI 3 document (JSON) |
| `-format` | `text` | `text` or `json` |
| `-fail-on` | `high` | Lowest severity that makes the command exit with `1` |
| `-public` | | Intentionally public endpoint, `"METHOD /path"` or `"/path"` (repeatable) |
| `-version` | | Print the version |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | No findings at or above `-fail-on` |
| `1` | At least one finding at or above `-fail-on` |
| `2` | Invalid flags, unreadable or unsupported document |

## YAML specs

The tool reads JSON to stay dependency-free. Most specs are written in YAML, so convert on the fly with [`yq`](https://github.com/mikefarah/yq):

```bash
yq -o=json openapi.yaml > /tmp/openapi.json && openapi-sentinel -input /tmp/openapi.json
```

Swagger 2.0 documents are rejected with a clear error; convert them to OpenAPI 3 first (for example with `swagger2openapi`).

## Using it in CI

```yaml
- name: Review API security
  run: |
    yq -o=json api/openapi.yaml > openapi.json
    go run github.com/httpEduardo/openapi-sentinel/cmd/openapi-sentinel@latest -input openapi.json
```

## Project layout

```
cmd/openapi-sentinel/   CLI, flags and output
internal/spec/          Parsing and security inheritance
internal/audit/         Rules and severities
examples/               A deliberately flawed spec and a clean one
```

## Development

```bash
make test
make lint
make run
```

## Limitations

The spec describes intent, not behavior. A clean report means the documented API asks for authentication everywhere it should — it doesn't prove the implementation enforces it, or that authorization (who can access *which* object) is correct. Use this alongside integration tests and a real API security test.

## License

[MIT](LICENSE)
