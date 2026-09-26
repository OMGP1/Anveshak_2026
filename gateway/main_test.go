package main

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T) (*gateway, string) {
	t.Helper()
	audit, err := openAudit(filepath.Join(t.TempDir(), "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { audit.file.Close() })
	token := strings.Repeat("test-secret", 4)
	sum := sha256.Sum256([]byte(token))
	upstream, _ := url.Parse("http://127.0.0.1:8000")
	g, err := newGateway(upstream, []user{{"alice", "admin", hex.EncodeToString(sum[:])}}, strings.Repeat("s", 48), "localhost:8443", false, audit)
	if err != nil {
		t.Fatal(err)
	}
	g.proxy = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	return g, token
}
func request(g *gateway, method, path, token, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://localhost:8443"+path, nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	return w
}
func TestAuthenticationAndBoundaries(t *testing.T) {
	g, token := fixture(t)
	for _, c := range []struct {
		method, path, token, origin string
		want                        int
	}{
		{"GET", "/api/status", "", "", 401}, {"GET", "/", "", "", 303},
		{"GET", "/api/status", token, "", 204}, {"POST", "/api/replay/start", token, "https://evil.invalid", 403},
		{"DELETE", "/api/status", token, "", 403}, {"POST", "/unexpected", token, "", 403},
	} {
		if got := request(g, c.method, c.path, c.token, c.origin).Code; got != c.want {
			t.Fatalf("%+v: %d", c, got)
		}
	}
	r := httptest.NewRequest("GET", "https://evil.invalid/api/status", nil)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	for i := 0; i < cap(g.slots); i++ {
		g.slots <- struct{}{}
	}
	if request(g, "GET", "/api/status", token, "").Code != 503 {
		t.Fatal("unbounded requests")
	}
}
func TestRoles(t *testing.T) {
	for _, role := range []string{"viewer", "operator", "admin"} {
		for _, path := range []string{"/api/training/start", "/api/replay/start", "/api/live/start", "/api/live/stop"} {
			want := role == "admin" || (role == "operator" && path != "/api/training/start")
			if allowed(user{Role: role}, httptest.NewRequest("POST", path, nil)) != want {
				t.Fatal(role, path)
			}
		}
	}
}
func TestLoginSessionAndLogout(t *testing.T) {
	g, token := fixture(t)
	if request(g, "GET", "/login", "", "").Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("Native login forms need their same-origin Origin header")
	}
	if request(g, "POST", "/login", "", "null").Code != 403 {
		t.Fatal("Opaque cross-origin forms must remain blocked")
	}
	r := httptest.NewRequest("POST", "https://localhost:8443/login", strings.NewReader("token="+url.QueryEscape(token)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://localhost:8443")
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe cookie")
	}
	r = httptest.NewRequest("GET", "https://localhost:8443/api/status", nil)
	r.AddCookie(cookie)
	if _, ok := g.authenticate(r); !ok {
		t.Fatal("session failed")
	}
	g.sessions[cookie.Value] = session{User: g.users[0], Expires: time.Now().Add(-time.Second)}
	if _, ok := g.authenticate(r); ok {
		t.Fatal("expired session accepted")
	}
	g.sessions[cookie.Value] = session{User: g.users[0], Expires: time.Now().Add(time.Minute)}
	r = httptest.NewRequest("POST", "https://localhost:8443/logout", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 303 || len(g.sessions) != 0 {
		t.Fatal("logout failed")
	}
}
func TestLoginRateLimitAndBodyLimit(t *testing.T) {
	g, token := fixture(t)
	for i := 0; i < 30; i++ {
		request(g, "POST", "/login", "", "")
	}
	if request(g, "POST", "/login", "", "").Code != 429 {
		t.Fatal("unbounded login")
	}
	r := httptest.NewRequest("POST", "https://localhost:8443/api/replay/start", strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	g.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal(w.Code)
	}
}
func TestAuditRecoveryTamperAndFailure(t *testing.T) {
	g, token := fixture(t)
	if request(g, "POST", "/api/replay/stop", token, "").Code != 204 {
		t.Fatal("mutation failed")
	}
	name := g.audit.file.Name()
	g.audit.file.Close()
	restored, err := openAudit(name)
	if err != nil {
		t.Fatal(err)
	}
	restored.file.Close()
	if request(g, "POST", "/api/replay/stop", token, "").Code != 503 {
		t.Fatal("audit failure not closed")
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), "alice", "mallory", 1))
	if err = os.WriteFile(name, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = openAudit(name); err == nil {
		t.Fatal("tamper accepted")
	}
}

func TestAuditRejectsMissingFinalNewline(t *testing.T) {
	g, token := fixture(t)
	request(g, "POST", "/api/replay/stop", token, "")
	name := g.audit.file.Name()
	g.audit.file.Close()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, raw[:len(raw)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = openAudit(name); err == nil {
		t.Fatal("unterminated audit accepted")
	}
}
func TestProxyStripsSpoofedCredentials(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-SIH-Gateway") != strings.Repeat("s", 48) || r.Header.Get("X-SIH-Role") != "admin" {
			t.Error("trust headers incorrect")
		}
		if r.Header.Get("X-SIH-User") != "alice" {
			t.Error("trusted actor header incorrect")
		}
		if r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" {
			t.Error("untrusted identity forwarded")
		}
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 48) {
			t.Error("training auth not injected")
		}
		io.WriteString(w, "ok")
	}))
	defer backend.Close()
	g, token := fixture(t)
	up, _ := url.Parse(backend.URL)
	real, err := newGateway(up, g.users, g.secret, g.publicHost, false, g.audit)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "https://localhost:8443/api/training/start", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("Cookie", "stolen=secret")
	r.Header.Set("X-SIH-Role", "viewer")
	r.Header.Set("X-SIH-User", "spoofed-user")
	r.Header.Set("X-Forwarded-For", "spoof")
	w := httptest.NewRecorder()
	real.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
}
