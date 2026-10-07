# locksmith: API Key Authentication and Management Service in Go

I built Locksmith as a backend learning project: a local HTTP service for creating, managing, and authenticating API keys with Go and SQLite.

I used **OpenCode CLI with Codex**, and most of the code was written by AI. I directed the work, asked for explanations, requested changes, and performed manual checks. I am sharing it as a learning project, not as fully audited production software.

> **My testing is still incomplete.** Full key-lifecycle/persistence tests and concurrent-request/race-detection coverage remain unfinished. I also have documented limitations to address before any public deployment.

## What I built

- Securely generated, 64-character hexadecimal API keys with UUIDs, names, and timestamps.
- SQLite persistence that stores key hashes rather than raw secrets.
- Admin-only creation, listing, retrieval, revocation, and deletion.
- A protected endpoint for active ordinary API keys.
- Input safeguards, timeouts, diagnostic logging, and Ctrl+C graceful shutdown.
- A service bound to **`127.0.0.1:8083`**, accessible only from the same computer.

## My learning phases

The headings for phases 1–6 are retrospective summaries of the modules I built, not recovered verbatim roadmap titles. Phases 7–10 retain the agreed later topics.

### Phase 1 — Go and HTTP foundations
I established the Go project and a working HTTP server. I learned how requests reach routes and how the service sends responses.

### Phase 2 — JSON requests and basic endpoints
I built the home, health, and echo endpoints and worked with JSON input/output, HTTP methods, and response status codes.

### Phase 3 — API-key generation
I added cryptographically secure random secrets, hexadecimal encoding, UUID record identifiers, names, and creation timestamps.

### Phase 4 — Key-management lifecycle
I built creation, listing, retrieval, revocation, and deletion. Records initially lived in an in-memory map.

### Phase 5 — Credential storage and shared-state safety
I stored SHA-256 hashes instead of raw keys, kept secrets out of metadata responses, and protected the former shared map against concurrent access.

### Phase 6 — Authentication and admin authorization
I separated ordinary-key authentication from administrator permissions. I covered Bearer credentials, revocation, and the difference between 401 and 403.

### Phase 7 — SQLite persistence
I moved creation, reads, revocation, deletion, and authentication into SQLite, replacing the shared map. I learned SQL parameters and missing-record handling. I discussed transactions and migrations but deliberately excluded a migration runner.

### Phase 8 — Concurrency and robustness
I covered request-body limits, strict JSON, consistent HTTP errors/method handling, and server timeouts. I also restricted the database pool to one connection. The stricter input checks currently apply to key creation, not echo.

### Phase 9 — Automated testing: incomplete
My agreed topics were handler tests with `httptest`, authentication/admin-permission tests, lifecycle/persistence tests, and concurrent-request tests/race detection. I implemented four tests for selected handler and permission cases; I left the last two topics unfinished.

### Phase 10 — Production polish
I covered configuration, safe logging, graceful shutdown, and deployment/security basics. I configured local safeguards, but I have not deployed the service publicly or configured HTTPS.

## Requirements and project files

I currently target **Windows PowerShell** and a Go toolchain compatible with **Go 1.26.3**, as declared in `go.mod`.
I use `github.com/google/uuid` and `modernc.org/sqlite`; a separate SQLite server is not required.

| File | Purpose |
|---|---|
| `main.go` | Service, authentication, database setup, and endpoints. |
| `main_test.go` | My partial automated test suite. |
| `go.mod`, `go.sum` | Dependency versions and checksums. |
| `.gitignore` | Excludes local environment files, databases, logs, and executables. |

I store the database at **`%LOCALAPPDATA%\Locksmith\locksmith.db`**, outside the project/OneDrive checkout.

## My two types of credentials

| Credential | Purpose |
|---|---|
| Admin credential | Configured in `LOCKSMITH_ADMIN_KEY`; allows all key-management operations. |
| Ordinary API key | Returned when I create a key; allows `/api/protected` while active. |

The admin credential must be exactly 64 hexadecimal characters. I send credentials as `Authorization: Bearer <credential>`.
An ordinary key does not become an administrator: management access returns **403**. Missing, invalid, or revoked credentials return **401**.
The record UUID is not an authentication secret. My admin credential is separate from stored ordinary keys and does not by itself grant protected-endpoint access.

## Setup: server window and client window

I use two PowerShell windows. The **server/admin-setup window** configures the credential and runs Locksmith; the **client window** sends requests. Windows Administrator elevation is not needed.

### 1. Prepare the server window

**Paste in the server window**, opened in the project folder. Replace the example path if needed. This downloads the project dependencies.

```powershell
Set-Location "C:\path\to\locksmith"
go mod download
```

### 2. Configure the admin credential

**Paste in the same server window.** This generates a credential only if one is absent; it does not print or save the secret into a file.

```powershell
if ([string]::IsNullOrEmpty($env:LOCKSMITH_ADMIN_KEY)) {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($bytes)
    $rng.Dispose()
    $env:LOCKSMITH_ADMIN_KEY = [BitConverter]::ToString($bytes).Replace("-", "").ToLowerInvariant()
}
```

An existing malformed credential is not repaired by this block; the service rejects it at startup. I never publish real credentials or screenshots containing them.

### 3. Open the client window and start Locksmith

**Paste in the server window.** The first command opens a client that inherits the admin setting; the second starts the service. Leave this server window running.

```powershell
Start-Process powershell -WorkingDirectory (Get-Location).Path
go run .
```

### 4. Prepare the newly opened client window

**Paste in the new client window**, not the server window. This prepares authenticated calls and checks that Locksmith is reachable. Expected health result: `status: ok`.

```powershell
if ([string]::IsNullOrEmpty($env:LOCKSMITH_ADMIN_KEY)) {
    throw "Launch this client from the configured server window."
}
$baseUrl = "http://127.0.0.1:8083"
$adminHeaders = @{ Authorization = "Bearer $env:LOCKSMITH_ADMIN_KEY" }
Invoke-RestMethod -Uri "$baseUrl/health"
```

## Calling my endpoints

**Every command in this section goes in the client window.** Run creation before the commands that use its returned key, and run revocation/deletion last.
I use `Invoke-RestMethod` for parsed JSON, `Invoke-WebRequest` when I want status/headers, and `curl.exe -i` to inspect raw responses or expected errors. I use `curl.exe`, not PowerShell's possible `curl` alias.

| Method | Endpoint | Access | Success |
|---|---|---|---|
| GET | `/` | Public | 200 |
| GET | `/health` | Public | 200 |
| POST | `/echo` | Public | 200 |
| POST | `/api/keys` | Admin | 201 |
| GET | `/api/keys` | Admin | 200 |
| GET | `/api/keys/{id}` | Admin | 200 |
| GET | `/api/protected` | Active ordinary key | 200 |
| POST | `/api/keys/{id}/revoke` | Admin | 204 |
| DELETE | `/api/keys/{id}` | Admin | 204 |

### Home and health
**Client window:** these public GET calls confirm the welcome response and server reachability. Health is not a live database check.

```powershell
Invoke-RestMethod -Uri "$baseUrl/"
Invoke-RestMethod -Uri "$baseUrl/health"
```

### Send a POST request to echo
**Client window:** this submits JSON and returns the same message. No credential is needed.

```powershell
$echoBody = @{ message = "Hello from PowerShell" } | ConvertTo-Json
Invoke-RestMethod -Uri "$baseUrl/echo" -Method Post -ContentType "application/json" -Body $echoBody
```

### Create an ordinary API key
**Client window:** this admin-authenticated POST creates a record. Expected: **201** and a `Location` header. The displayed output omits the secret; keep the returned key privately because I cannot retrieve its raw value later.

```powershell
$body = @{ name = "my-learning-client" } | ConvertTo-Json
$response = Invoke-WebRequest -UseBasicParsing -Uri "$baseUrl/api/keys" -Method Post -ContentType "application/json" -Headers $adminHeaders -Body $body
$created = $response.Content | ConvertFrom-Json
$response.StatusCode
$response.Headers["Location"]
$created | Select-Object id, name, created_at
```

If I only need parsed JSON, I can use this **instead**. Running both creation commands creates two separate keys.

```powershell
$created = Invoke-RestMethod -Uri "$baseUrl/api/keys" -Method Post -ContentType "application/json" -Headers $adminHeaders -Body $body
```

### Authenticate with the ordinary key
**Client window:** this uses the key just created. Expected: **200**, `{"message":"You are authenticated"}`.

```powershell
$keyHeaders = @{ Authorization = "Bearer $($created.key)" }
Invoke-RestMethod -Uri "$baseUrl/api/protected" -Headers $keyHeaders
```

### List and retrieve key metadata
**Client window:** these admin GET calls list all records and retrieve the newly created record. Both return **200** without secrets or hashes; an empty list is `{}`.

```powershell
Invoke-RestMethod -Uri "$baseUrl/api/keys" -Headers $adminHeaders
Invoke-RestMethod -Uri "$baseUrl/api/keys/$($created.id)" -Headers $adminHeaders
```

### Check access rejection
**Client window, before revoking:** the first call uses an ordinary key on a management route and should return **403**. The second sends no credential and should return **401**. These are expected responses, not server crashes.

```powershell
curl.exe -i -H "Authorization: Bearer $($created.key)" "$baseUrl/api/keys"
curl.exe -i "$baseUrl/api/protected"
```

### Revoke the key
**Client window:** the POST disables the key but keeps its record, returning **204** with no body. The following protected call should now return **401**. There is no unrevoke endpoint.

```powershell
curl.exe -i -X POST -H "Authorization: Bearer $env:LOCKSMITH_ADMIN_KEY" "$baseUrl/api/keys/$($created.id)/revoke"
curl.exe -i -H "Authorization: Bearer $($created.key)" "$baseUrl/api/protected"
```

### Delete the record
**Client window:** DELETE permanently removes the record and returns **204**. The subsequent retrieval, or a repeated deletion, should return **404**.

```powershell
curl.exe -i -X DELETE -H "Authorization: Bearer $env:LOCKSMITH_ADMIN_KEY" "$baseUrl/api/keys/$($created.id)"
curl.exe -i -H "Authorization: Bearer $env:LOCKSMITH_ADMIN_KEY" "$baseUrl/api/keys/$($created.id)"
```

## Restarting and recovering my setup

- **Server window:** press Ctrl+C, wait for shutdown, then paste `go run .` again in that same terminal. I keep both windows open; restarting there does not erase the admin setting or database records.
- **Client window:** to check persistence, reuse the protected-call command after a restart **before revoking/deleting**. Creating a fresh key would not prove the old key survived.
- If the client loses admin access, I stop the server, repeat the credential/client-launch setup, and use the **new** client window. Existing clients do not automatically receive changed environment settings.
- Closing both terminals can lose the temporary admin setting. Changing the admin credential does not delete ordinary records. Previously created response data is not carried into a new client; a lost raw ordinary key cannot be recovered from its stored hash.
- **Client window:** `([string]$env:LOCKSMITH_ADMIN_KEY).Length` checks presence without printing the secret. Zero means missing; 64 does not prove a match. A failed health connection is different from HTTP 401.

## My safeguards and current limitations

- Key creation enforces a 1,024-byte read limit, strict single-value JSON, and trimmed names of 1–128 bytes. **Echo does not have these stricter checks.**
- Errors are plain text: 400 invalid input, 401 authentication, 403 permission denial, 404 missing record, 405 unsupported method, 413 oversized body, and 500 internal failure. Management authentication happens before method checks.
- Timeouts are 5s for headers, 10s for the full request, 10s for the response-writing window, and 60s for idle connections. Writing timeouts do not automatically stop handler code.
- Ctrl+C allows active requests up to 5s to finish. Force-killing or closing the terminal is not the same graceful path; Linux termination handling is not implemented.
- I log timestamped internal errors without deliberately logging credentials, hashes, headers, or bodies. I keep client-facing errors generic.
- My single SQLite connection simplifies local access, but does not eliminate external locking. I deliberately have no migration runner; existing schemas are not automatically upgraded.
- Windows database-path handling is not a cross-platform deployment configuration. I need to protect the database and backups with appropriate filesystem access.
- **I would not expose this publicly as-is:** HTTP does not encrypt credentials. HTTPS and further review are needed; I have not configured public hosting. Pagination, key expiry, and broader permission roles are not implemented.

## Build and my incomplete tests

**Paste in a terminal opened in the project folder.** These commands build the executable, run static checks, and run the existing tests; they do not start the server.

```powershell
go build -o locksmith.exe .
go vet ./...
go test ./... -count=1
```

**Server window:** I can run `.\locksmith.exe` instead of `go run .` with the same admin setup. I do not run both at once on port 8083.
My four tests cover method rejection, missing credentials, matching admin access, and active/revoked/unknown ordinary-key permissions, using fake requests and isolated test storage.
**Still unfinished:** full lifecycle/persistence tests and concurrent-request/race-detection coverage. Environment loading, shutdown timing, and other edge cases also lack dedicated tests. Passing this suite is not a security audit.

## Publishing and my stopping point

I include `main.go`, `main_test.go`, `go.mod`, `go.sum`, `README.md`, and `.gitignore`. I exclude real credentials, `.env`, databases, executables, logs, and secret-bearing screenshots. Ignoring a file does not erase old commits; I must rotate exposed credentials.

**Project-folder terminal, only if it is not already a Git repository:** this prepares a first commit. Review the staged changes before running the final command.

```powershell
git init
git add README.md .gitignore main.go main_test.go go.mod go.sum
git status
git diff --cached
git commit -m "Add Locksmith learning project"
```

I can then create a GitHub repository and follow its remote/push instructions. These setup steps do not publish anything automatically. I have not chosen a license; public visibility alone does not grant unrestricted reuse.
I consider this a reasonable stopping point for an **AI-assisted learning project with partial testing**, not a production-ready service. The two unfinished Phase 9 topics remain clear future work.
