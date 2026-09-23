// Package hookserver is the loopback listener Claude Code's http hooks reach:
// 127.0.0.1:7317 with the phone's HookServer contract byte for byte
// (RELAY.md §4; the phone's bridge-ingress.md), plus the daemon's control
// surface under /clair/ctl for the CLI. Every hook is handed to a Sink as a
// request record; the server itself reads nothing of a hook but the two
// fields the phone's 400 rule needs and the permission mode (record.Hook),
// until a decide is answered: the answer is checked against the request it
// answers (internal/hookout).
package hookserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/envelope"
	"claircode.app/clair-agent/internal/hookout"
	"claircode.app/clair-agent/internal/hostname"
	"claircode.app/clair-agent/internal/record"
)

const (
	// ListenDefault is where the phone's snippet points (RELAY.md §4).
	ListenDefault = "127.0.0.1:7317"
	// MaxBodyBytes is the phone's cap on a hook body: over it is 413.
	MaxBodyBytes = 4 << 20
	// On shutdown Serve waits shutdownGrace for handlers; held decides are
	// released by the tunnel before that (draft). A slow client's headers are
	// bounded by readHeaderTimeout.
	shutdownGrace     = 2 * time.Second
	readHeaderTimeout = 10 * time.Second
)

// Sink receives the tunnelled requests.
type Sink interface {
	// Enqueue takes a fire-and-forget request (/hook/event, /statusline,
	// /ping). It must not block on I/O: the hook is answered 204 regardless.
	Enqueue(req record.Record, hook record.Hook) error
	// Hold takes a decide and waits for the phone's response record or the
	// timeout. ok=false is "no decision" (204); err is set only when ctx
	// ended — the client left or the server is shutting down — and nothing
	// is written then.
	Hold(ctx context.Context, req record.Record, hook record.Hook, timeout time.Duration) (resp record.Record, ok bool, err error)
}

// Controller answers the control surface.
type Controller interface {
	Status(ctx context.Context) ctl.Status
	Reload(ctx context.Context) error
	// ReleasePair stops a pair and hands its file to the caller;
	// ctl.ErrNotFound is 404.
	ReleasePair(ctx context.Context, pairID string) error
}

// Options configure a Server.
type Options struct {
	// Token is the hook bearer (agent.json's token). Empty refuses every hook.
	Token string
	// AdminToken guards /clair/ctl. Empty refuses every control call.
	AdminToken string
	// MaxBodyBytes overrides MaxBodyBytes; 0 keeps the default.
	MaxBodyBytes int64
	Sink         Sink
	Control      Controller
	Logger       *slog.Logger
	// Now and Entropy mint request ids.
	Now     func() time.Time
	Entropy io.Reader
}

// Server is the listener's handler.
type Server struct {
	token   []byte
	admin   []byte
	maxBody int64
	sink    Sink
	control Controller
	log     *slog.Logger
	now     func() time.Time
	entropy io.Reader
}

// New builds a server. Sink and Entropy are required.
func New(opts Options) (*Server, error) {
	if opts.Sink == nil {
		return nil, errors.New("hookserver: a Sink is required")
	}
	if opts.Entropy == nil {
		return nil, errors.New("hookserver: an entropy source is required")
	}
	s := &Server{
		token:   []byte(opts.Token),
		admin:   []byte(opts.AdminToken),
		maxBody: opts.MaxBodyBytes,
		sink:    opts.Sink,
		control: opts.Control,
		log:     opts.Logger,
		now:     opts.Now,
		entropy: opts.Entropy,
	}
	if s.maxBody <= 0 {
		s.maxBody = MaxBodyBytes
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.now == nil {
		s.now = time.Now
	}
	return s, nil
}

// Listen opens the loopback listener.
func Listen(ctx context.Context, addr string) (net.Listener, error) {
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("hookserver: listen %s: %w", addr, err)
	}
	return ln, nil
}

// IsLoopback reports whether addr binds a loopback interface only. Anything
// else exposes the hook bearer to the network (a devcontainer setup wants
// that; nothing else does).
func IsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Serve runs the listener until ctx ends, then shuts down within the grace
// period. It owns the serving goroutine and returns once it has stopped.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           s,
		ReadHeaderTimeout: readHeaderTimeout,
		MaxHeaderBytes:    1 << 16,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ln) }()
	select {
	case <-ctx.Done():
		graceCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownGrace)
		defer cancel()
		if err := srv.Shutdown(graceCtx); err != nil {
			_ = srv.Close()
		}
		<-errc
		return nil
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("hookserver: serve: %w", err)
	}
}

// ServeHTTP routes in the phone's order: a path outside both prefixes is 404
// before any credential is looked at; under a prefix the bearer comes first,
// then the path, then the method.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	switch {
	case strings.HasPrefix(path, ctl.Prefix):
		if !authorized(r, s.admin) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.serveControl(w, r)
	case strings.HasPrefix(path, record.PathPrefix):
		if !authorized(r, s.token) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		s.serveHook(w, r)
	default:
		http.NotFound(w, r)
	}
}

// authorized checks `Authorization: Bearer <token>` in constant time. The
// prefix is exact — the phone's guard also accepts a bare token, which this
// server does not.
func authorized(r *http.Request, token []byte) bool {
	if len(token) == 0 {
		return false
	}
	presented, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), token) == 1
}

func (s *Server) serveHook(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case record.PathEvent:
		s.event(w, r)
	case record.PathDecide:
		s.decide(w, r)
	case record.PathStatusline:
		s.statusline(w, r)
	case record.PathPing:
		s.ping(w, r)
	case record.PathStatus:
		s.status(w, r)
	default:
		http.NotFound(w, r)
	}
}

// requireMethod answers 405 with Allow for the wrong method.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	w.WriteHeader(http.StatusMethodNotAllowed)
	return false
}

// readBody reads a capped body, answering 413 or 400 itself.
func (s *Server) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.ContentLength > s.maxBody {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return nil, false
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, s.maxBody))
	if err != nil {
		if _, tooLarge := errors.AsType[*http.MaxBytesError](err); tooLarge {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
		} else {
			w.WriteHeader(http.StatusBadRequest)
		}
		return nil, false
	}
	return body, true
}

// topLevel holds the two fields the phone's HookInput.parse requires and the
// one the release rule reads (record.Hook, ADR 2026-09.34qh). The session id
// is checked for presence and never read: a hook without one is refused here
// rather than tunnelled to a phone that would drop it anyway, leaving a
// decide hanging for its whole timeout.
type topLevel struct {
	SessionID      string `json:"session_id"`
	HookEventName  string `json:"hook_event_name"`
	PermissionMode string `json:"permission_mode"`
}

// hookFields validates a hook body and returns what the agent may know of
// it, or answers 400.
func hookFields(w http.ResponseWriter, body []byte) (record.Hook, bool) {
	var f topLevel
	if err := json.Unmarshal(body, &f); err != nil || f.SessionID == "" || f.HookEventName == "" {
		w.WriteHeader(http.StatusBadRequest)
		return record.Hook{}, false
	}
	return record.Hook{Event: f.HookEventName, Mode: f.PermissionMode}, true
}

// request builds the request record: the path, the query, the one forwarded
// header, and the body verbatim.
func (s *Server) request(r *http.Request, body []byte) (record.Record, error) {
	id, err := envelope.NewID(s.now(), s.entropy)
	if err != nil {
		return record.Record{}, err
	}
	rec := record.Record{Kind: record.KindRequest, ReqID: id, Path: r.URL.Path, Body: body}
	if q := r.URL.Query(); len(q) > 0 {
		rec.Query = make(map[string]string, len(q))
		for k := range q {
			rec.Query[k] = q.Get(k)
		}
	}
	// Only a name in the sanitised-hostname set is forwarded: the header is
	// the one thing of the request's metadata the phone sees, and a hook
	// whose headers were shaped elsewhere must not carry anything else
	// through it (ADR 2026-09.ut2g).
	if host := strings.TrimSpace(r.Header.Get(record.HostHeader)); hostname.Valid(host) {
		rec.Headers = map[string]string{record.HostHeader: host}
	}
	return rec, nil
}

// enqueue builds and hands over a fire-and-forget record; the answer is 204
// whatever happens to it, as on the phone.
func (s *Server) enqueue(w http.ResponseWriter, r *http.Request, body []byte, hook record.Hook) {
	rec, err := s.request(r, body)
	if err != nil {
		s.log.Error("request id not minted", "path", r.URL.Path, "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := s.sink.Enqueue(rec, hook); err != nil {
		s.log.Warn("hook not queued", "path", r.URL.Path, "req_id", rec.ReqID, "bytes", len(body), "error", err.Error())
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) event(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	hook, ok := hookFields(w, body)
	if !ok {
		return
	}
	s.enqueue(w, r, body, hook)
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	hook, ok := hookFields(w, body)
	if !ok {
		return
	}
	rec, err := s.request(r, body)
	if err != nil {
		s.log.Error("request id not minted", "path", r.URL.Path, "error", err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	timeout := record.DecideTimeout(r.URL.Query())
	resp, ok, err := s.sink.Hold(r.Context(), rec, hook, timeout)
	if err != nil {
		// The client is gone or the server is stopping; there is nobody to
		// answer. The sink has told the phone.
		s.log.Debug("decide abandoned", "req_id", rec.ReqID, "error", err.Error())
		return
	}
	if !ok || resp.Status != http.StatusOK || len(resp.Body) == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	// The phone may allow or deny what it was shown, nothing more: its answer
	// is checked against this request and rebuilt (ADR 2026-09.w4ww).
	out, err := hookout.Check(body, resp.Body)
	if err != nil {
		s.log.Warn("decide answer refused", "req_id", rec.ReqID, "bytes", len(resp.Body), "error", err.Error())
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

func (s *Server) statusline(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	// The phone accepts any JSON object here; `null` and arrays are 400.
	trimmed := strings.TrimLeftFunc(string(body), func(c rune) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' })
	if !json.Valid(body) || !strings.HasPrefix(trimmed, "{") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.enqueue(w, r, body, record.Hook{})
}

func (s *Server) ping(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	body, ok := s.readBody(w, r)
	if !ok {
		return
	}
	// The phone tolerates any body here; a ping is the installer saying hello.
	s.enqueue(w, r, body, record.Hook{})
}

// status answers GET /clair/v1/status locally with the agent's own state
// (RELAY.md §4.1 has it round-trip to the phone; that is a later addition).
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}
	s.writeStatus(w, r)
}

func (s *Server) writeStatus(w http.ResponseWriter, r *http.Request) {
	var st ctl.Status
	if s.control != nil {
		st = s.control.Status(r.Context())
	}
	data, err := json.Marshal(st)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(data)
}

func (s *Server) serveControl(w http.ResponseWriter, r *http.Request) {
	if s.control == nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case r.URL.Path == ctl.PathStatus:
		if requireMethod(w, r, http.MethodGet) {
			s.writeStatus(w, r)
		}
	case r.URL.Path == ctl.PathReload:
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if err := s.control.Reload(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case strings.HasPrefix(r.URL.Path, ctl.PathPairs):
		if !requireMethod(w, r, http.MethodDelete) {
			return
		}
		id := strings.TrimPrefix(r.URL.Path, ctl.PathPairs)
		err := s.control.ReleasePair(r.Context(), id)
		switch {
		case err == nil:
			w.WriteHeader(http.StatusNoContent)
		case errors.Is(err, ctl.ErrNotFound):
			http.NotFound(w, r)
		default:
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	default:
		http.NotFound(w, r)
	}
}
