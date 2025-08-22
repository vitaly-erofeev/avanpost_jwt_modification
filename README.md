# Avanpost JWT Modification (Traefik Middleware Plugin)

Middleware for Traefik that verifies an incoming Avanpost JWT, extracts the user identity (sub), resolves a user_id from your user service, then issues a new locally signed JWT with additional custom claims. The middleware replaces the incoming Authorization header with the new token before proxying to your backend.

This repository contains the plugin implementation and metadata to be used with Traefik's plugin system.

## Features
- Validates incoming Bearer tokens against an Avanpost JWKS URL.
- Extracts `sub` and profile claims from the validated token.
- Resolves user data from your user service and obtains IDs/roles.
- Generates a new RS256-signed JWT with claims: `user` (object with IDs/roles), `sub`, `iat`, `exp` (+1 hour), `iss`="local-gateway".
- Replaces the incoming Authorization header with the new token for upstream requests.

## Requirements
- Traefik with plugin support (experimental plugins or Traefik Pilot-style manifest).
- Go 1.20+ (for local development/building the plugin).

## Configuration
The plugin exposes the following configuration fields (see `.traefik.yml`):

- `sso` (string): URL to the Avanpost JWKS endpoint used to validate incoming JWTs.
- `key` (string): Filesystem path to an RSA private key in PEM format used to sign the new JWT.
- `userservice` (string): Base URL of your user service to resolve the user by `sub` and profile data. The middleware will POST JSON to `${userservice}/{sub}`.
- `apikey` (string): API key sent as `X-Api-Key` header to your user service.

Example test data from `.traefik.yml`:
```yaml
# .traefik.yml
displayName: Avanpost JWT Modification
type: middleware
import: github.com/vitaly-erofeev/avanpost_jwt_modification
summary: >
  Middleware для проверки токена Avanpost, получения данных пользователя и генерации нового JWT
  с добавленными кастомными клеймами для проксирования на backend.
testData:
  sso: "https://avanpost.example.com/.well-known/jwks.json"
  key: "/keys/local.key"
  userservice: "http://user-service.local/api/users"
  apikey: "example-secret-key"
```

## How it works (request flow)
1. Read `Authorization` header (`Bearer <token>`). If missing → 401.
2. Validate token using JWKS from `sso`. If invalid → 401.
3. Extract `sub` claim (and profile fields) from the validated token.
4. Resolve `user` by calling your `userservice` with `X-Api-Key: <apikey>` and payload containing profile data; endpoint: `${userservice}/{sub}`.
5. Create a new JWT (RS256) signed with `key` containing claims: `user`, `sub`, `iat`, `exp`(+1h), `iss`="local-gateway".
6. Replace `Authorization` header with the new token and forward to the next handler.

## Usage with Traefik (file provider example)
Add the plugin to your Traefik static configuration (e.g., via `traefik.yml`) and reference this repository import path. Then configure the middleware dynamically.

Example dynamic config (YAML):
```yaml
http:
  middlewares:
    avanpost-jwt-mod:
      plugin:
        avanpost_jwt_modification:
          sso: "https://avanpost.example.com/.well-known/jwks.json"
          key: "/run/secrets/local.key"   # path inside Traefik container
          userservice: "http://user-service:8080/api/users"
          apikey: "example-secret-key"

  routers:
    api:
      rule: Host(`api.local`)
      entryPoints: ["web"]
      service: api-svc
      middlewares: ["avanpost-jwt-mod"]

  services:
    api-svc:
      loadBalancer:
        servers:
          - url: "http://backend:8000"
```

Static config snippet for enabling the plugin (example):
```yaml
experimental:
  plugins:
    avanpost_jwt_modification:
      moduleName: github.com/vitaly-erofeev/avanpost_jwt_modification
      version: v0.0.0 # or a tag/commit you publish
```

Note: The exact static configuration may vary depending on your Traefik version and how you load plugins (pilot vs experimental). Refer to Traefik documentation for details on plugin installation.

## Generating a local RSA private key
If you need a test key:
```bash
openssl genrsa -out local.key 2048
openssl rsa -in local.key -pubout -out local.pub
```
Mount `local.key` into the Traefik container and set `key` to its path.

## Local development
- The function `getUserData` performs an HTTP POST to your backend. Adjust the URL shape, payload, and returned JSON to match your environment.
- Build checks:
```bash
go build ./...
```
- Lint and tests: none provided yet; consider adding unit tests for token verification and claim generation.

## Error handling
- 401 Unauthorized: missing Authorization header, invalid token, invalid claims, or user not found.
- 500 Internal Server Error: issues parsing the private key or signing the token.

## Security notes
- Store the private `key` securely (e.g., Docker secret or Kubernetes secret) and restrict file permissions.
- Ensure time synchronization for correct `iat`/`exp` handling and signature validation.
- Validate and sanitize responses from your `userservice` before including them in JWT claims.

## License
This project’s license is not specified. Add a LICENSE file if you need to define usage terms.
