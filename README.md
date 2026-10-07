# locksmith: api key authentication and management service in go

i built locksmith as a backend learning project: a local http service for creating, managing, and authenticating api keys with go and sqlite.

i used **opencode cli with codex**, and most of the code was written by ai. the process involved directing the work, asking for explanations, requesting changes, and performing manual checks. this is a learning project, not fully audited production software.

> **testing is still incomplete.** full key-lifecycle/persistence tests and concurrent-request/race-detection coverage remain unfinished. documented limitations also need attention before any public deployment.

## what was built

- securely generated, 64-character hexadecimal api keys with uuids, names, and timestamps.
- sqlite persistence that stores key hashes rather than raw secrets.
- admin-only creation, listing, retrieval, revocation, and deletion.
- a protected endpoint for active ordinary api keys.
- input safeguards, timeouts, diagnostic logging, and ctrl+c graceful shutdown.
- a service bound to **`127.0.0.1:8083`**, accessible only from the same computer.

## learning phases

these phases summarize my learning journey, from a basic http service to persistent key management and local operational safeguards.

### phase 1: go and http foundations
started with the go project and a working http server, learning how requests reach routes and how the service sends responses.

### phase 2: json requests and basic endpoints
built the home, health, and echo endpoints and worked with json input/output, http methods, and response status codes.

### phase 3: api-key generation
added cryptographically secure random secrets, hexadecimal encoding, uuid record identifiers, names, and creation timestamps.

### phase 4: key-management lifecycle
built creation, listing, retrieval, revocation, and deletion. records initially lived in an in-memory map.

### phase 5: credential storage and shared-state safety
stored sha-256 hashes instead of raw keys, kept secrets out of metadata responses, and protected the former shared map against concurrent access.

### phase 6: authentication and admin authorization
separated ordinary-key authentication from administrator permissions, covering bearer credentials, revocation, and the difference between 401 and 403.

### phase 7: sqlite persistence
moved creation, reads, revocation, deletion, and authentication into sqlite, replacing the shared map. covered sql parameters and missing-record handling. transactions and migrations were discussed, but a migration runner was deliberately excluded.

### phase 8: concurrency and robustness
covered request-body limits, strict json, consistent http errors/method handling, and server timeouts. also restricted the database pool to one connection. the stricter input checks currently apply to key creation, not echo.

### phase 9: automated testing, incomplete
my testing plan covered handler tests with `httptest`, authentication/admin-permission tests, lifecycle/persistence tests, and concurrent-request tests/race detection. four tests cover selected handler and permission cases; the last two topics remain unfinished.

### phase 10: production polish
covered configuration, safe logging, graceful shutdown, and deployment/security basics. local safeguards are configured, but public deployment and https are not.

## requirements and project files

the current setup targets **windows powershell** and a go toolchain compatible with **go 1.26.3**, as declared in `go.mod`.
dependencies are `github.com/google/uuid` and `modernc.org/sqlite`; a separate sqlite server is not required.

| file | purpose |
|---|---|
| `main.go` | service, authentication, database setup, and endpoints. |
| `main_test.go` | partial automated test suite. |
| `go.mod`, `go.sum` | dependency versions and checksums. |
| `.gitignore` | excludes local environment files, databases, logs, and executables. |

the database lives at **`%localappdata%\locksmith\locksmith.db`**, outside the project/onedrive checkout.

## two types of credentials

| credential | purpose |
|---|---|
| admin credential | configured in `locksmith_admin_key`; allows all key-management operations. |
| ordinary api key | returned during key creation; allows `/api/protected` while active. |

the admin credential must be exactly 64 hexadecimal characters. credentials are sent as `authorization: bearer <credential>`.
an ordinary key does not become an administrator: management access returns **403**. missing, invalid, or revoked credentials return **401**.
the record uuid is not an authentication secret. the admin credential is separate from stored ordinary keys and does not by itself grant protected-endpoint access.

## setup: server window and client window

the **server/admin-setup window** configures the credential and runs locksmith; the **client window** sends requests. windows administrator elevation is not needed.
the lowercase powershell commands and environment names below work on windows, where their casing is not significant.

### 1. prepare the server window

**paste in the server window**, opened in the project folder. replace the example path if needed. this downloads the project dependencies.

```powershell
set-location "c:\path\to\locksmith"
go mod download
```

### 2. configure the admin credential

**paste in the same server window.** this generates a credential only if one is absent; it does not print or save the secret into a file.

```powershell
if ([string]::isnullorempty($env:locksmith_admin_key)) {
    $bytes = new-object byte[] 32
    $rng = [system.security.cryptography.randomnumbergenerator]::create()
    $rng.getbytes($bytes)
    $rng.dispose()
    $env:locksmith_admin_key = [bitconverter]::tostring($bytes).replace("-", "").tolowerinvariant()
}
```

an existing malformed credential is not repaired by this block; the service rejects it at startup. never publish real credentials or screenshots containing them.

### 3. open the client window and start locksmith

**paste in the server window.** the first command opens a client that inherits the admin setting; the second starts the service. leave this server window running.

```powershell
start-process powershell -workingdirectory (get-location).path
go run .
```

### 4. prepare the newly opened client window

**paste in the new client window**, not the server window. this prepares authenticated calls and checks that locksmith is reachable. expected health result: `status: ok`.

```powershell
if ([string]::isnullorempty($env:locksmith_admin_key)) {
    throw "launch this client from the configured server window."
}
$baseurl = "http://127.0.0.1:8083"
$adminheaders = @{ authorization = "bearer $env:locksmith_admin_key" }
invoke-restmethod -uri "$baseurl/health"
```

## calling the endpoints

**every command in this section goes in the client window.** run creation before the commands that use its returned key, and run revocation/deletion last.
use `invoke-restmethod` for parsed json, `invoke-webrequest` for status/headers, and `curl.exe --include` for raw responses or expected errors. use `curl.exe`, not powershell's possible `curl` alias.

| method | endpoint | access | success |
|---|---|---|---|
| get | `/` | public | 200 |
| get | `/health` | public | 200 |
| post | `/echo` | public | 200 |
| post | `/api/keys` | admin | 201 |
| get | `/api/keys` | admin | 200 |
| get | `/api/keys/{id}` | admin | 200 |
| get | `/api/protected` | active ordinary key | 200 |
| post | `/api/keys/{id}/revoke` | admin | 204 |
| delete | `/api/keys/{id}` | admin | 204 |

### home and health
**client window:** these public get calls confirm the welcome response and server reachability. health is not a live database check.

```powershell
invoke-restmethod -uri "$baseurl/"
invoke-restmethod -uri "$baseurl/health"
```

### send a post request to echo
**client window:** this submits json and returns the same message. no credential is needed.

```powershell
$echobody = @{ message = "hello from powershell" } | convertto-json
invoke-restmethod -uri "$baseurl/echo" -method post -contenttype "application/json" -body $echobody
```

### create an ordinary api key
**client window:** this admin-authenticated post creates a record. expected: **201** and a `location` header. the displayed output omits the secret; keep the returned key privately because its raw value cannot be retrieved later.

```powershell
$body = @{ name = "my-learning-client" } | convertto-json
$response = invoke-webrequest -usebasicparsing -uri "$baseurl/api/keys" -method post -contenttype "application/json" -headers $adminheaders -body $body
$created = $response.content | convertfrom-json
$response.statuscode
$response.headers["location"]
$created | select-object id, name, created_at
```

for parsed json without status/headers, use this **instead**. running both creation commands creates two separate keys.

```powershell
$created = invoke-restmethod -uri "$baseurl/api/keys" -method post -contenttype "application/json" -headers $adminheaders -body $body
```

### authenticate with the ordinary key
**client window:** this uses the key just created. expected: **200** with an authentication confirmation.

```powershell
$keyheaders = @{ authorization = "bearer $($created.key)" }
invoke-restmethod -uri "$baseurl/api/protected" -headers $keyheaders
```

### list and retrieve key metadata
**client window:** these admin get calls list all records and retrieve the newly created record. both return **200** without secrets or hashes; an empty list is `{}`.

```powershell
invoke-restmethod -uri "$baseurl/api/keys" -headers $adminheaders
invoke-restmethod -uri "$baseurl/api/keys/$($created.id)" -headers $adminheaders
```

### check access rejection
**client window, before revoking:** the first call uses an ordinary key on a management route and should return **403**. the second sends no credential and should return **401**. these are expected responses, not server crashes.

```powershell
curl.exe --include --header "authorization: bearer $($created.key)" "$baseurl/api/keys"
curl.exe --include "$baseurl/api/protected"
```

### revoke the key
**client window:** the post disables the key but keeps its record, returning **204** with no body. the following protected call should now return **401**. there is no unrevoke endpoint.

```powershell
(invoke-webrequest -usebasicparsing -uri "$baseurl/api/keys/$($created.id)/revoke" -method post -headers $adminheaders).statuscode
curl.exe --include --header "authorization: bearer $($created.key)" "$baseurl/api/protected"
```

### delete the record
**client window:** delete permanently removes the record and returns **204**. the subsequent retrieval, or a repeated deletion, should return **404**.

```powershell
(invoke-webrequest -usebasicparsing -uri "$baseurl/api/keys/$($created.id)" -method delete -headers $adminheaders).statuscode
curl.exe --include --header "authorization: bearer $env:locksmith_admin_key" "$baseurl/api/keys/$($created.id)"
```

## restarting and recovering the setup

- **server window:** press ctrl+c, wait for shutdown, then paste `go run .` again in that same terminal. keep both windows open; restarting there does not erase the admin setting or database records.
- **client window:** to check persistence, reuse the protected-call command after a restart **before revoking/deleting**. creating a fresh key would not prove the old key survived.
- if the client loses admin access, stop the server, repeat the credential/client-launch setup, and use the **new** client window. existing clients do not automatically receive changed environment settings.
- closing both terminals can lose the temporary admin setting. changing the admin credential does not delete ordinary records. previously created response data is not carried into a new client; a lost raw ordinary key cannot be recovered from its stored hash.
- **client window:** `([string]$env:locksmith_admin_key).length` checks presence without printing the secret. zero means missing; 64 does not prove a match. a failed health connection is different from http 401.

## safeguards and current limitations

- key creation enforces a 1,024-byte read limit, strict single-value json, and trimmed names of 1-128 bytes. **echo does not have these stricter checks.**
- errors are plain text: 400 invalid input, 401 authentication, 403 permission denial, 404 missing record, 405 unsupported method, 413 oversized body, and 500 internal failure. management authentication happens before method checks.
- timeouts are 5s for headers, 10s for the full request, 10s for the response-writing window, and 60s for idle connections. writing timeouts do not automatically stop handler code.
- ctrl+c allows active requests up to 5s to finish. force-killing or closing the terminal is not the same graceful path; linux termination handling is not implemented.
- timestamped internal-error logging does not deliberately include credentials, hashes, headers, or bodies. client-facing errors remain generic.
- a single sqlite connection simplifies local access, but does not eliminate external locking. a migration runner was deliberately excluded; existing schemas are not automatically upgraded.
- windows database-path handling is not a cross-platform deployment configuration. protect the database and backups with appropriate filesystem access.
- **do not expose this publicly as-is:** http does not encrypt credentials. https and further review are needed; public hosting is not configured. pagination, key expiry, and broader permission roles are not implemented.

## build and incomplete tests

**paste in a terminal opened in the project folder.** these commands build the executable, run static checks, and run the existing tests; they do not start the server.

```powershell
go build -o locksmith.exe .
go vet ./...
go test ./... -count=1
```

**server window:** run `.\locksmith.exe` instead of `go run .` with the same admin setup if using the binary. do not run both at once on port 8083.
the four tests cover method rejection, missing credentials, matching admin access, and active/revoked/unknown ordinary-key permissions, using fake requests and isolated test storage.
**still unfinished:** full lifecycle/persistence tests and concurrent-request/race-detection coverage. environment loading, shutdown timing, and other edge cases also lack dedicated tests. passing this suite is not a security audit.

## publishing and stopping point

include the source files, dependency files, readme, and `.gitignore`. exclude real credentials, `.env`, databases, executables, logs, and secret-bearing screenshots. ignoring a file does not erase old commits; rotate exposed credentials.

**project-folder terminal, only if it is not already a git repository:** this prepares a first commit. review the staged changes before running the final command.

```powershell
git init
git add *.md .gitignore main.go main_test.go go.mod go.sum
git status
git diff --cached
git commit -m "add locksmith learning project"
```

create a github repository and follow its remote/push instructions. these setup steps do not publish anything automatically. no license has been chosen; public visibility alone does not grant unrestricted reuse.
for now, i consider this a reasonable stopping point for an **ai-assisted learning project with partial testing**, not a production-ready service. the two unfinished phase 9 topics remain clear future work.
