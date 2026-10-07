package main

import (
	"crypto/sha256"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGetKeyHandlerRejectsPOST(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/api/keys/example", nil)
	response := httptest.NewRecorder()

	getKeyHandler(nil).ServeHTTP(response, request)

	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("want 405, got %d", response.Code)
	}
	if response.Header().Get("Allow") != http.MethodGet {
		t.Fatal("want Allow: GET")
	}
}

func TestRequireAPIKeyRejectsMissingCredential(t *testing.T) {
	request := httptest.NewRequest(http.MethodGet, "/api/protected", nil)
	response := httptest.NewRecorder()

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("unauthenticated request reached protected handler")
	})

	requireAPIKey(nil, protected).ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", response.Code)
	}
	if response.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Fatal("want WWW-Authenticate: Bearer")
	}
}

func TestRequireAdminAcceptsAdmin(t *testing.T) {
	adminKey := strings.Repeat("a", 64)
	adminHash := sha256.Sum256([]byte(adminKey))

	request := httptest.NewRequest(http.MethodGet, "/api/keys", nil)
	request.Header.Set("Authorization", "Bearer "+adminKey)
	response := httptest.NewRecorder()

	management := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	requireAdmin(nil, adminHash, management).ServeHTTP(response, request)

	if response.Code != http.StatusNoContent {
		t.Fatalf("want 204, got %d", response.Code)
	}
}

func TestOrdinaryKeyPermissions(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })

	_, err = db.Exec(`CREATE TABLE api_keys (key_hash BLOB, revoked INTEGER)`)
	if err != nil {
		t.Fatal(err)
	}

	activeKey := strings.Repeat("b", 64)
	revokedKey := strings.Repeat("c", 64)
	activeHash := sha256.Sum256([]byte(activeKey))
	revokedHash := sha256.Sum256([]byte(revokedKey))
	adminHash := sha256.Sum256([]byte(strings.Repeat("a", 64)))

	_, err = db.Exec(`INSERT INTO api_keys VALUES (?, 0), (?, 1)`,
		activeHash[:], revokedHash[:])
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	cases := []struct {
		name          string
		key           string
		wantProtected int
		wantAdmin     int
	}{
		{"active", activeKey, http.StatusNoContent, http.StatusForbidden},
		{"revoked", revokedKey, http.StatusUnauthorized, http.StatusUnauthorized},
		{"unknown", strings.Repeat("d", 64), http.StatusUnauthorized, http.StatusUnauthorized},
	}

	for _, tc := range cases {
		request := httptest.NewRequest(http.MethodGet, "/", nil)
		request.Header.Set("Authorization", "Bearer "+tc.key)

		protected := httptest.NewRecorder()
		requireAPIKey(db, next).ServeHTTP(protected, request)
		if protected.Code != tc.wantProtected {
			t.Fatalf("%s: protected want %d, got %d", tc.name, tc.wantProtected, protected.Code)
		}

		admin := httptest.NewRecorder()
		requireAdmin(db, adminHash, next).ServeHTTP(admin, request)
		if admin.Code != tc.wantAdmin {
			t.Fatalf("%s: admin want %d, got %d", tc.name, tc.wantAdmin, admin.Code)
		}
	}
}
