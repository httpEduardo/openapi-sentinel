# OpenAPI Sentinel

![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

**A quick security review for OpenAPI 3 specifications.**

OpenAPI Sentinel checks API definitions for common access-control and configuration issues, then reports the affected endpoints with severity levels. Use it during design review or in CI to catch mistakes before release.

## Checks include

- Operations without effective authentication, including optional security requirements
- Undefined security schemes and API keys placed in query parameters
- Public `null` origins, plain HTTP servers, and deprecated operations

The report is a review aid: a clean specification does not prove that the running API enforces authentication or authorization.

## Quick start

Requires Go 1.21 or newer.

```bash
go install github.com/httpEduardo/openapi-sentinel/cmd/openapi-sentinel@latest
openapi-sentinel -input openapi.json
```

To try the included example:

```bash
git clone https://github.com/httpEduardo/openapi-sentinel.git
cd openapi-sentinel
go run ./cmd/openapi-sentinel -input examples/demo-api.json
```

Use `-format json` for machine-readable output or `-trusted` to mark intentionally public endpoints:

```bash
openapi-sentinel -input openapi.json -trusted "GET /health" -format json
```

## License

[MIT](LICENSE)
