// The gateway handles operator traffic only. It never connects to monitored traffic endpoints.
package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

type user struct {
	ID        string `json:"id"`
	Role      string `json:"role"`
	TokenHash string `json:"token_sha256"`
}
type session struct {
	User    user
	Expires time.Time
}
type auditRecord struct {
	Time     string `json:"time"`
	User     string `json:"user"`
	Action   string `json:"action"`
	Previous string `json:"previous"`
	Hash     string `json:"hash"`
}
type auditLog struct {
	sync.Mutex
	file *os.File
	head string
}

func auditHash(r auditRecord) string {
	r.Hash = ""
	b, _ := json.Marshal(r)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func openAudit(path string) (*auditLog, error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	a := &auditLog{file: f}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if info.Size() > 0 {
		last := make([]byte, 1)
		if _, err = f.ReadAt(last, info.Size()-1); err != nil || last[0] != '\n' {
			f.Close()
			return nil, errors.New("gateway audit has an unterminated record")
		}
	}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		var r auditRecord
		if json.Unmarshal(scanner.Bytes(), &r) != nil || r.Previous != a.head || r.Hash != auditHash(r) {
			f.Close()
			return nil, errors.New("gateway audit chain is corrupt")
		}
		a.head = r.Hash
	}
	if err = scanner.Err(); err != nil {
		f.Close()
		return nil, err
	}
	return a, nil
}
func (a *auditLog) append(id, action string) error {
	a.Lock()
	defer a.Unlock()
	r := auditRecord{Time: time.Now().UTC().Format(time.RFC3339Nano), User: id, Action: action, Previous: a.head}
	r.Hash = auditHash(r)
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if _, err = a.file.Write(append(b, '\n')); err != nil {
		return err
	}
	if err = a.file.Sync(); err != nil {
		return err
	}
	a.head = r.Hash
	return nil
}

type gateway struct {
	users      []user
	secret     string
	dev        bool
	publicHost string
	proxy      http.Handler
	audit      *auditLog
	mu         sync.Mutex
	sessions   map[string]session
	slots      chan struct{}
	loginStart time.Time
	loginCount int
}

func newGateway(upstream *url.URL, users []user, secret, host string, dev bool, audit *auditLog) (*gateway, error) {
	if len(secret) < 32 || len(users) == 0 || host == "" {
		return nil, errors.New("gateway secret, public host, and users are required")
	}
	for _, u := range users {
		if u.ID == "" || len(u.TokenHash) != 64 || (u.Role != "viewer" && u.Role != "operator" && u.Role != "admin") {
			return nil, errors.New("invalid user record")
		}
	}
	if upstream.Scheme != "http" || upstream.User != nil || upstream.RawQuery != "" || upstream.Path != "" {
		return nil, errors.New("upstream must be a private HTTP origin without credentials or path")
	}
	g := &gateway{users: users, secret: secret, publicHost: host, dev: dev, audit: audit, sessions: make(map[string]session), slots: make(chan struct{}, 128)}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.MaxConnsPerHost = 128
	transport.MaxIdleConnsPerHost = 32
	transport.ResponseHeaderTimeout = 15 * time.Second
	g.proxy = &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(upstream)
			p.Out.Host = p.In.Host
			p.Out.Header.Del("Forwarded")
			p.Out.Header.Del("X-Forwarded-For")
			p.Out.Header.Del("X-Forwarded-Host")
			p.Out.Header.Del("X-Forwarded-Proto")
			p.Out.Header.Del("Cookie")
			p.Out.Header.Del("Authorization")
			p.Out.Header.Del("X-SIH-Gateway")
			p.Out.Header.Del("X-SIH-Role")
			p.Out.Header.Del("X-SIH-User")
			p.Out.Header.Set("X-SIH-Gateway", g.secret)
			u := p.In.Context().Value(userKey{}).(user)
			p.Out.Header.Set("X-SIH-Role", u.Role)
			p.Out.Header.Set("X-SIH-User", u.ID)
			if p.Out.URL.Path == "/api/training/start" {
				p.Out.Header.Set("Authorization", "Bearer "+g.secret)
			}
		}, Transport: transport,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			http.Error(w, "backend unavailable", http.StatusBadGateway)
		},
	}
	return g, nil
}

type userKey struct{}

func (g *gateway) authenticate(r *http.Request) (user, bool) {
	if authorization := r.Header.Get("Authorization"); strings.HasPrefix(authorization, "Bearer ") {
		sum := sha256.Sum256([]byte(strings.TrimPrefix(authorization, "Bearer ")))
		digest := hex.EncodeToString(sum[:])
		for _, u := range g.users {
			if subtle.ConstantTimeCompare([]byte(digest), []byte(u.TokenHash)) == 1 {
				return u, true
			}
		}
	}
	cookie, err := r.Cookie("sih_session")
	if err != nil {
		return user{}, false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	s, ok := g.sessions[cookie.Value]
	if !ok || time.Now().After(s.Expires) {
		delete(g.sessions, cookie.Value)
		return user{}, false
	}
	return s.User, true
}
func (g *gateway) sameOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	scheme := "https"
	if g.dev {
		scheme = "http"
	}
	return origin == scheme+"://"+g.publicHost
}
func allowed(u user, r *http.Request) bool {
	if r.Method == "GET" || r.Method == "HEAD" {
		if strings.HasPrefix(r.URL.Path, "/api/cases") || strings.HasPrefix(r.URL.Path, "/api/reports/") {
			return u.Role == "operator" || u.Role == "admin"
		}
		return true
	}
	if r.Method != "POST" {
		return false
	}
	if r.URL.Path == "/api/training/start" {
		return u.Role == "admin"
	}
	if r.URL.Path == "/api/copilot/query" || (strings.HasPrefix(r.URL.Path, "/api/copilot/jobs/") && strings.HasSuffix(r.URL.Path, "/cancel")) {
		return u.Role == "viewer" || u.Role == "operator" || u.Role == "admin"
	}
	if strings.HasPrefix(r.URL.Path, "/api/cases/") || strings.HasPrefix(r.URL.Path, "/api/alerts/") && strings.HasSuffix(r.URL.Path, "/reviews") || strings.HasPrefix(r.URL.Path, "/api/reports/") {
		return u.Role == "operator" || u.Role == "admin"
	}
	switch r.URL.Path {
	case "/api/replay/start", "/api/replay/pause", "/api/replay/resume", "/api/replay/stop", "/api/live/start", "/api/live/stop":
		return u.Role == "operator" || u.Role == "admin"
	}
	return false
}

const loginHTML = `<!doctype html><html lang="en"><meta charset="utf-8"><title>SIH operator login</title><body><h1>Detection enclave login</h1><form method="post" action="/login"><label>Access token <input type="password" name="token" required autocomplete="current-password"></label><button>Sign in</button></form><p>Use your assigned viewer, operator, or administrator token. Do not share tokens.</p></body></html>`

func (g *gateway) login(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, loginHTML)
		return
	}
	if r.Method != "POST" || !g.sameOrigin(r) {
		http.Error(w, "request refused", 403)
		return
	}
	g.mu.Lock()
	if time.Since(g.loginStart) > time.Minute {
		g.loginStart = time.Now()
		g.loginCount = 0
	}
	g.loginCount++
	limited := g.loginCount > 30
	g.mu.Unlock()
	if limited {
		http.Error(w, "login rate limit reached", 429)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if r.ParseForm() != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	token := r.PostForm.Get("token")
	sum := sha256.Sum256([]byte(token))
	digest := hex.EncodeToString(sum[:])
	var account user
	for _, u := range g.users {
		if subtle.ConstantTimeCompare([]byte(digest), []byte(u.TokenHash)) == 1 {
			account = u
		}
	}
	if account.ID == "" {
		if g.audit.append("anonymous", "login-denied") != nil {
			http.Error(w, "audit unavailable", 503)
			return
		}
		http.Error(w, "invalid credentials", 401)
		return
	}
	if g.audit.append(account.ID, "login-allowed") != nil {
		http.Error(w, "audit unavailable", 503)
		return
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		http.Error(w, "session unavailable", 503)
		return
	}
	id := hex.EncodeToString(random)
	g.mu.Lock()
	for key, s := range g.sessions {
		if time.Now().After(s.Expires) {
			delete(g.sessions, key)
		}
	}
	if len(g.sessions) >= 128 {
		g.mu.Unlock()
		http.Error(w, "session capacity reached", 503)
		return
	}
	g.sessions[id] = session{account, time.Now().Add(30 * time.Minute)}
	g.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "sih_session", Value: id, Path: "/", MaxAge: 1800, HttpOnly: true, Secure: !g.dev, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (g *gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// no-referrer makes a native form POST serialize Origin as null (Fetch standard).
	// same-origin preserves our own login Origin without leaking referrers cross-site.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
	if !g.dev {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	}
	if r.Host != g.publicHost {
		http.Error(w, "untrusted host", 400)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		http.Error(w, "gateway capacity reached", 503)
		return
	}
	if r.URL.Path == "/login" {
		g.login(w, r)
		return
	}
	account, ok := g.authenticate(r)
	if !ok {
		if r.Method == "GET" && r.URL.Path == "/" {
			http.Redirect(w, r, "/login", 303)
		} else {
			http.Error(w, "authentication required", 401)
		}
		return
	}
	if !g.sameOrigin(r) {
		http.Error(w, "cross-origin request refused", 403)
		return
	}
	if r.URL.Path == "/logout" && r.Method == "POST" {
		if g.audit.append(account.ID, "logout") != nil {
			http.Error(w, "audit unavailable", 503)
			return
		}
		if c, err := r.Cookie("sih_session"); err == nil {
			g.mu.Lock()
			delete(g.sessions, c.Value)
			g.mu.Unlock()
		}
		http.SetCookie(w, &http.Cookie{Name: "sih_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: !g.dev, SameSite: http.SameSiteStrictMode})
		http.Redirect(w, r, "/login", 303)
		return
	}
	if !allowed(account, r) {
		http.Error(w, "role does not permit this action", 403)
		return
	}
	if r.ContentLength > 1<<20 {
		http.Error(w, "request too large", 413)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if r.Method != "GET" && r.Method != "HEAD" {
		if g.audit.append(account.ID, r.Method+" "+r.URL.Path) != nil {
			http.Error(w, "audit unavailable", 503)
			return
		}
	}
	// Request bodies, query strings, credentials, and packet data never enter the action audit.
	g.proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey{}, account)))
}

type limitedListener struct {
	net.Listener
	slots chan struct{}
}
type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error { err := c.Conn.Close(); c.once.Do(c.release); return err }
func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			return &limitedConn{Conn: c, release: func() { <-l.slots }}, nil
		default:
			c.Close()
		}
	}
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "gateway bind address")
	upstreamText := flag.String("upstream", "http://127.0.0.1:8000", "private detection API")
	host := flag.String("public-host", "localhost:8443", "exact browser host, including port")
	usersPath := flag.String("users", ".secrets/gateway-users.json", "token hashes and roles")
	secretPath := flag.String("backend-secret", ".secrets/backend-token", "shared backend secret")
	auditPath := flag.String("audit", "data/gateway-audit.jsonl", "append-only action audit")
	certificate := flag.String("cert", "", "TLS certificate PEM")
	key := flag.String("key", "", "TLS private key PEM")
	dev := flag.Bool("dev-http", false, "allow cleartext ONLY on loopback for local testing")
	flag.Parse()
	address, _, err := net.SplitHostPort(*listen)
	if err != nil {
		log.Fatal(err)
	}
	if *dev {
		ip := net.ParseIP(address)
		if ip == nil || !ip.IsLoopback() {
			log.Fatal("dev-http requires a numeric loopback listen address")
		}
	} else if *certificate == "" || *key == "" {
		log.Fatal("TLS certificate and key are required")
	}
	raw, err := os.ReadFile(*usersPath)
	if err != nil {
		log.Fatal(err)
	}
	var users []user
	if err = json.Unmarshal(raw, &users); err != nil {
		log.Fatal(err)
	}
	secret, err := os.ReadFile(*secretPath)
	if err != nil {
		log.Fatal(err)
	}
	audit, err := openAudit(*auditPath)
	if err != nil {
		log.Fatal(err)
	}
	defer audit.file.Close()
	upstream, err := url.Parse(*upstreamText)
	if err != nil {
		log.Fatal(err)
	}
	handler, err := newGateway(upstream, users, strings.TrimSpace(string(secret)), *host, *dev, audit)
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 * 1024, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}
	listener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	bounded := &limitedListener{Listener: listener, slots: make(chan struct{}, 256)}
	stopped := make(chan os.Signal, 1)
	signal.Notify(stopped, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-stopped
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	fmt.Printf("SIH gateway listening on %s; backend %s; TLS=%t\n", *listen, *upstreamText, !*dev)
	if *dev {
		err = server.Serve(bounded)
	} else {
		err = server.ServeTLS(bounded, *certificate, *key)
	}
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
