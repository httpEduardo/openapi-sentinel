# OpenAPI Sentinel

OpenAPI Sentinel inspects an OpenAPI v3 spec and flags endpoints without security coverage.

## Quick start

```bash
go run main.go --input spec.json
```

## Output

- Endpoints missing security requirements.
- Admin or destructive verbs highlighted for review.
