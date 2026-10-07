package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

type HealthResponse struct {
	Status string `json:"status"`
}

type EchoRequest struct {
	Message string `json:"message"`
}

type CreateKeyRequest struct {
	Name string `json:"name"`
}

type APIKey struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	KeyHash   [32]byte `json:"-"`
	CreatedAt string   `json:"created_at"`
	Revoked   bool     `json:"revoked"`
}

type CreateKeyResponse struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Key       string `json:"key"`
	CreatedAt string `json:"created_at"`
}

type APIKeyMetadata struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CreatedAt string `json:"created_at"`
	Revoked   bool   `json:"revoked"`
}

func requireAPIKey(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))

		if len(parts) != 2 ||
			!strings.EqualFold(parts[0], "Bearer") ||
			len(parts[1]) != 64 {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		providedHash := sha256.Sum256([]byte(parts[1]))
		var found int
		err := db.QueryRowContext(r.Context(), `
			SELECT 1 FROM api_keys
			WHERE key_hash = ? AND revoked = 0
		`, providedHash[:]).Scan(&found)
		if err == sql.ErrNoRows {
			w.Header().Set("WWW-Authenticate", "Bearer")
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err != nil {
			log.Printf("authentication lookup failed: %v", err)
			http.Error(w, "authentication storage unavailable", http.StatusInternalServerError)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// requireAdmin checks permission before running a key-management handler.
func requireAdmin(db *sql.DB, adminHash [32]byte, next http.Handler) http.Handler {
	// Valid ordinary keys get 403; missing, invalid, or revoked keys get 401.
	denyOrdinaryKey := requireAPIKey(db, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Fields(r.Header.Get("Authorization"))
		if len(parts) == 2 &&
			strings.EqualFold(parts[0], "Bearer") &&
			len(parts[1]) == 64 {
			providedHash := sha256.Sum256([]byte(parts[1]))
			if subtle.ConstantTimeCompare(providedHash[:], adminHash[:]) == 1 {
				// The admin credential matches: run the actual route handler.
				next.ServeHTTP(w, r)
				return
			}
		}

		// Not the admin credential: return 401 or 403 without managing keys.
		denyOrdinaryKey.ServeHTTP(w, r)
	})
}

// getKeyHandler retrieves one key's metadata from SQLite.
func getKeyHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		id := r.PathValue("id")
		var response APIKeyMetadata

		err := db.QueryRowContext(r.Context(), `
			SELECT id, name, created_at, revoked
			FROM api_keys
			WHERE id = ?
		`, id).Scan(
			&response.ID,
			&response.Name,
			&response.CreatedAt,
			&response.Revoked,
		)

		if err == sql.ErrNoRows {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}
		if err != nil {
			log.Printf("retrieve key failed: %v", err)
			http.Error(w, "failed to retrieve key", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	}
}

func main() {

	adminSecret := os.Getenv("LOCKSMITH_ADMIN_KEY")

	if decoded, err := hex.DecodeString(adminSecret); err != nil || len(decoded) != 32 {
		log.Println("LOCKSMITH_ADMIN_KEY must contain 64 hexadecimal characters")
		return
	}

	adminHash := sha256.Sum256([]byte(adminSecret))

	// Open SQLite for key storage and authentication.
	dataDir := os.Getenv("LOCALAPPDATA")
	if dataDir == "" {
		log.Println("LOCALAPPDATA must be set to locate the database")
		return
	}
	dbDir := filepath.Join(dataDir, "Locksmith")
	if err := os.MkdirAll(dbDir, 0700); err != nil {
		log.Println("database directory error:", err)
		return
	}
	dbPath := filepath.Join(dbDir, "locksmith.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		log.Println("database error:", err)
		return
	}
	db.SetMaxOpenConns(1)
	defer db.Close()

	if err := db.Ping(); err != nil {
		log.Println("database connection error:", err)
		return
	}
	log.Println("SQLite connection ready")

	// Ensure the API key table exists.
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id TEXT PRIMARY KEY NOT NULL,
			name TEXT NOT NULL,
			key_hash BLOB NOT NULL UNIQUE CHECK (length(key_hash) = 32),
			created_at TEXT NOT NULL,
			revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1))
		)
	`)
	if err != nil {
		log.Println("database table error:", err)
		return
	}
	log.Println("API keys table ready")

	// Home endpoint
	http.HandleFunc("/{$}", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		response := map[string]string{
			"message": "Welcome to Locksmith",
		}

		json.NewEncoder(w).Encode(response)
	})

	// Health check
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		response := HealthResponse{
			Status: "ok",
		}

		json.NewEncoder(w).Encode(response)
	})

	// Echo endpoint
	http.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request EchoRequest

		err := json.NewDecoder(r.Body).Decode(&request)
		if err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/json")

		response := map[string]string{
			"message": request.Message,
		}

		json.NewEncoder(w).Encode(response)
	})

	// Create API key
	http.Handle("/api/keys", requireAdmin(db, adminHash, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		if r.Method == http.MethodGet {
			rows, err := db.QueryContext(r.Context(), `
				SELECT id, name, created_at, revoked FROM api_keys
			`)
			if err != nil {
				log.Printf("list keys failed: %v", err)
				http.Error(w, "failed to list keys", http.StatusInternalServerError)
				return
			}
			defer rows.Close()

			response := make(map[string]APIKeyMetadata)
			for rows.Next() {
				var key APIKeyMetadata
				if err := rows.Scan(&key.ID, &key.Name, &key.CreatedAt, &key.Revoked); err != nil {
					log.Printf("scan key metadata failed: %v", err)
					http.Error(w, "failed to list keys", http.StatusInternalServerError)
					return
				}
				response[key.ID] = key
			}
			if err := rows.Err(); err != nil {
				log.Printf("iterate keys failed: %v", err)
				http.Error(w, "failed to list keys", http.StatusInternalServerError)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(response)
			return
		}

		if r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var request CreateKeyRequest

		r.Body = http.MaxBytesReader(w, r.Body, 1024)

		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()

		err := decoder.Decode(&request)
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}

			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		var extra json.RawMessage
		if err := decoder.Decode(&extra); err != io.EOF {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
				return
			}

			http.Error(w, "body must contain exactly one JSON value", http.StatusBadRequest)
			return
		}

		request.Name = strings.TrimSpace(request.Name)

		if request.Name == "" || len(request.Name) > 128 {
			http.Error(w, "name must be 1 to 128 bytes", http.StatusBadRequest)
			return
		}

		// Generate 32 cryptographically secure random bytes.
		randomBytes := make([]byte, 32)

		_, err = rand.Read(randomBytes)
		if err != nil {
			log.Printf("generate key failed: %v", err)
			http.Error(w, "failed to generate key", http.StatusInternalServerError)
			return
		}

		// Convert the random bytes into a hexadecimal string.
		key := hex.EncodeToString(randomBytes)

		apiKey := APIKey{
			ID:        uuid.New().String(),
			Name:      request.Name,
			KeyHash:   sha256.Sum256([]byte(key)),
			CreatedAt: time.Now().Format(time.RFC3339),
		}

		// Persist the record before returning its secret to the client.
		_, err = db.ExecContext(r.Context(), `
			INSERT INTO api_keys (id, name, key_hash, created_at, revoked)
			VALUES (?, ?, ?, ?, ?)
		`, apiKey.ID, apiKey.Name, apiKey.KeyHash[:], apiKey.CreatedAt, apiKey.Revoked)
		if err != nil {
			log.Printf("store key failed: %v", err)
			http.Error(w, "failed to store key", http.StatusInternalServerError)
			return
		}

		response := CreateKeyResponse{
			ID:        apiKey.ID,
			Name:      apiKey.Name,
			Key:       key,
			CreatedAt: apiKey.CreatedAt,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Location", "/api/keys/"+apiKey.ID)
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(response)
	})))

	// Retrieve or delete one API key
	readKey := getKeyHandler(db)
	http.Handle("/api/keys/{id}", requireAdmin(db, adminHash, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")

		if r.Method == http.MethodDelete {
			result, err := db.ExecContext(r.Context(), `
				DELETE FROM api_keys WHERE id = ?
			`, id)
			if err != nil {
				log.Printf("delete key failed: %v", err)
				http.Error(w, "failed to delete key", http.StatusInternalServerError)
				return
			}
			count, err := result.RowsAffected()
			if err != nil {
				log.Printf("read delete result failed: %v", err)
				http.Error(w, "failed to delete key", http.StatusInternalServerError)
				return
			}
			if count == 0 {
				http.Error(w, "key not found", http.StatusNotFound)
				return
			}

			w.WriteHeader(http.StatusNoContent)
			return
		}

		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET, DELETE")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		readKey.ServeHTTP(w, r)
	})))

	http.Handle("/api/protected", requireAPIKey(db, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{
				"message": "You are authenticated",
			})
		},
	)))

	http.Handle("/api/keys/{id}/revoke", requireAdmin(db, adminHash, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		id := r.PathValue("id")

		result, err := db.ExecContext(r.Context(), `
			UPDATE api_keys SET revoked = 1 WHERE id = ?
		`, id)
		if err != nil {
			log.Printf("revoke key failed: %v", err)
			http.Error(w, "failed to revoke key", http.StatusInternalServerError)
			return
		}
		count, err := result.RowsAffected()
		if err != nil {
			log.Printf("read revoke result failed: %v", err)
			http.Error(w, "failed to revoke key", http.StatusInternalServerError)
			return
		}
		if count == 0 {
			http.Error(w, "key not found", http.StatusNotFound)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	})))

	log.Println("Locksmith running on http://localhost:8083")

	server := &http.Server{
		Addr:              "127.0.0.1:8083",
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	stopContext, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	done := make(chan struct{})
	go func() {
		<-stopContext.Done()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("shutdown failed: %v", err)
			_ = server.Close()
		}
		close(done)
	}()

	err = server.ListenAndServe()
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Println("server error:", err)
		return
	}

	<-done
	log.Println("Locksmith stopped")
}
