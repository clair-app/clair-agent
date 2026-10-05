package record

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const reqID = "01ARYZ6S41TSV4RRFFQ69G5FAV"

func TestHookEventName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want string
		err  error
	}{
		{name: "top level", body: `{"session_id":"s","hook_event_name":"PreToolUse","tool_input":{}}`, want: "PreToolUse"},
		{name: "after nested objects and arrays", body: `{"a":{"hook_event_name":"Nested","b":[1,{"c":null}]},"d":[[]],"hook_event_name":"Stop"}`, want: "Stop"},
		{name: "nested only", body: `{"tool_input":{"hook_event_name":"Nested"}}`, err: ErrNoEventName},
		{name: "first occurrence wins", body: `{"hook_event_name":"First","hook_event_name":"Second"}`, want: "First"},
		{name: "missing", body: `{"session_id":"s"}`, err: ErrNoEventName},
		{name: "empty string", body: `{"hook_event_name":""}`, err: ErrNoEventName},
		{name: "not a string", body: `{"hook_event_name":7}`, err: ErrNoEventName},
		{name: "object value", body: `{"hook_event_name":{"x":1}}`, err: ErrNoEventName},
		{name: "array body", body: `[{"hook_event_name":"Stop"}]`, err: ErrNotObject},
		{name: "string body", body: `"Stop"`, err: ErrNotObject},
		{name: "not json", body: `not json`, err: ErrNotObject},
		{name: "empty", body: ``, err: ErrNotObject},
		{name: "truncated", body: `{"tool_input":{"a":`, err: ErrNotObject},
		{name: "whitespace and unicode", body: "{\n  \"cwd\": \"/tmp/ü\",\n  \"hook_event_name\" : \"SessionStart\"\n}", want: "SessionStart"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := HookEventName([]byte(tt.body))
			if !errors.Is(err, tt.err) {
				t.Fatalf("HookEventName: err = %v, want %v", err, tt.err)
			}
			if got != tt.want {
				t.Fatalf("HookEventName = %q, want %q", got, tt.want)
			}
		})
	}
}

// The release rule's marker (ADR 2026-10.gw8w): a subagent's decide, or a
// bubble one, in an interactive session or one whose hooks block predates
// the entrypoint header; never one from `claude -p` or another launcher.
func TestHookBubbled(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		hook Hook
		want bool
	}{
		{name: "bubble without a header", hook: Hook{Mode: ModeBubble}, want: true},
		{name: "subagent in auto mode without a header", hook: Hook{Mode: "auto", Subagent: true}, want: true},
		{name: "subagent in an interactive session", hook: Hook{Mode: "auto", Subagent: true, Entrypoint: EntrypointCLI}, want: true},
		{name: "bubble in an interactive session", hook: Hook{Mode: ModeBubble, Entrypoint: EntrypointCLI}, want: true},
		{name: "main agent in auto mode", hook: Hook{Mode: "auto"}, want: false},
		{name: "main agent in an interactive session", hook: Hook{Mode: "default", Entrypoint: EntrypointCLI}, want: false},
		{name: "subagent in claude -p", hook: Hook{Mode: "default", Subagent: true, Entrypoint: "sdk-cli"}, want: false},
		{name: "bubble in claude -p", hook: Hook{Mode: ModeBubble, Subagent: true, Entrypoint: "sdk-cli"}, want: false},
		{name: "subagent under the Agent SDK", hook: Hook{Subagent: true, Entrypoint: "sdk-ts"}, want: false},
		{name: "subagent under another launcher", hook: Hook{Subagent: true, Entrypoint: "claude-vscode"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.hook.Bubbled(); got != tt.want {
				t.Errorf("%+v.Bubbled() = %v, want %v", tt.hook, got, tt.want)
			}
		})
	}
}

func TestMarshalKeepsBodyBytes(t *testing.T) {
	t.Parallel()

	body := `{"hook_event_name":"PreToolUse","tool_input":{"command":"cat a > b && echo <done> \"é\" é"}}`
	r := &Record{N: 42, Kind: KindRequest, ReqID: reqID, Path: PathEvent, Headers: map[string]string{HostHeader: "walter-laptop"}, Body: []byte(body)}
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"n":42,"kind":"request","reqId":"` + reqID + `","path":"/clair/v1/hook/event","headers":{"X-Clair-Host":"walter-laptop"},"body":` + body + `}`
	if string(data) != want {
		t.Fatalf("Marshal =\n%s\nwant\n%s", data, want)
	}
	back, err := Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !bytes.Equal(back.Body, []byte(body)) {
		t.Fatalf("round-tripped body =\n%s\nwant\n%s", back.Body, body)
	}
}

func TestMarshalCompactsButDoesNotReencode(t *testing.T) {
	t.Parallel()

	r := &Record{N: 1, Kind: KindRequest, ReqID: reqID, Path: PathEvent, Body: []byte("{ \"hook_event_name\" : \"Stop\" ,\n \"z\":1.50 }")}
	data, err := Marshal(r)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if want := `"body":{"hook_event_name":"Stop","z":1.50}`; !strings.Contains(string(data), want) {
		t.Fatalf("Marshal = %s, want it to contain %s (whitespace removed, numbers untouched)", data, want)
	}
}

func TestMarshalRejectsInvalidBody(t *testing.T) {
	t.Parallel()

	_, err := Marshal(&Record{N: 1, Kind: KindRequest, ReqID: reqID, Path: PathEvent, Body: []byte(`{not json`)})
	if err == nil {
		t.Fatal("Marshal with an invalid body: want an error")
	}
}

func TestWireFormPerKind(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		r    Record
		want string
	}{
		{
			name: "decide request",
			r:    Record{N: 3, Kind: KindRequest, ReqID: reqID, Path: PathDecide, Query: map[string]string{"timeout": "86400"}, Body: []byte(`{"hook_event_name":"PermissionRequest"}`)},
			want: `{"n":3,"kind":"request","reqId":"` + reqID + `","path":"/clair/v1/hook/decide","query":{"timeout":"86400"},"body":{"hook_event_name":"PermissionRequest"}}`,
		},
		{
			name: "response with body",
			r:    Record{N: 7, Kind: KindResponse, ReqID: reqID, Status: 200, Body: []byte(`{"hookSpecificOutput":{}}`)},
			want: `{"n":7,"kind":"response","reqId":"` + reqID + `","status":200,"body":{"hookSpecificOutput":{}}}`,
		},
		{
			name: "empty response",
			r:    Record{N: 8, Kind: KindResponse, ReqID: reqID, Status: 204},
			want: `{"n":8,"kind":"response","reqId":"` + reqID + `","status":204}`,
		},
		{
			name: "hello",
			r:    Record{N: 1, Kind: KindControl, Control: ControlHello, Name: "Pixel 9 Pro", Snippet: []byte(`{"hooks":{}}`)},
			want: `{"n":1,"kind":"control","control":"hello","name":"Pixel 9 Pro","snippet":{"hooks":{}}}`,
		},
		{
			name: "hello-ack",
			r:    Record{N: 1, Kind: KindControl, Control: ControlHelloAck, Hostname: "walter-laptop", AgentVersion: "v0.1.0"},
			want: `{"n":1,"kind":"control","control":"hello-ack","hostname":"walter-laptop","agentVersion":"v0.1.0"}`,
		},
		{
			name: "reset",
			r:    Record{N: 2, Kind: KindControl, Control: ControlReset},
			want: `{"n":2,"kind":"control","control":"reset"}`,
		},
		{
			name: "cancel",
			r:    Record{N: 9, Kind: KindControl, Control: ControlCancel, ReqID: reqID},
			want: `{"n":9,"kind":"control","reqId":"` + reqID + `","control":"cancel"}`,
		},
		{
			name: "cancel with a reason",
			r:    Record{N: 9, Kind: KindControl, Control: ControlCancel, ReqID: reqID, Reason: CancelTerminal},
			want: `{"n":9,"kind":"control","reqId":"` + reqID + `","control":"cancel","reason":"terminal"}`,
		},
		{
			name: "hello with a presence policy",
			r:    Record{N: 1, Kind: KindControl, Control: ControlHello, Name: "Pixel 9 Pro", Presence: &Presence{IdleThresholdSec: new(120)}},
			want: `{"n":1,"kind":"control","control":"hello","name":"Pixel 9 Pro","presence":{"idleThresholdSec":120}}`,
		},
		{
			name: "policy switching the rule off",
			r:    Record{N: 4, Kind: KindControl, Control: ControlPolicy, Presence: &Presence{IdleThresholdSec: new(0)}},
			want: `{"n":4,"kind":"control","control":"policy","presence":{"idleThresholdSec":0}}`,
		},
		{
			name: "presence request",
			r:    Record{N: 5, Kind: KindRequest, ReqID: reqID, Path: PathPresence, Headers: map[string]string{IdleHeader: "3400"}, Body: []byte(`{"idleMs":3400}`)},
			want: `{"n":5,"kind":"request","reqId":"` + reqID + `","path":"/clair/v1/hook/presence","headers":{"X-Clair-Idle-Ms":"3400"},"body":{"idleMs":3400}}`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := Marshal(&tt.r)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(data) != tt.want {
				t.Fatalf("Marshal =\n%s\nwant\n%s", data, tt.want)
			}
			back, err := Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			again, err := Marshal(back)
			if err != nil {
				t.Fatalf("Marshal again: %v", err)
			}
			if string(again) != tt.want {
				t.Fatalf("second Marshal =\n%s\nwant\n%s", again, tt.want)
			}
		})
	}
}

func TestUnmarshalIgnoresUnknownFields(t *testing.T) {
	t.Parallel()

	r, err := Unmarshal([]byte(`{"n":1,"kind":"control","control":"hello","name":"p","epoch":3,"future":{"x":[1]}}`))
	if err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if r.Control != ControlHello || r.Name != "p" {
		t.Fatalf("Unmarshal = %+v, want the hello fields", r)
	}
}

func TestValidate(t *testing.T) {
	t.Parallel()

	var unknown *UnknownControlError
	tests := []struct {
		name string
		r    Record
		want error
	}{
		{name: "request", r: Record{N: 1, Kind: KindRequest, ReqID: reqID, Path: PathEvent}},
		{name: "request without n", r: Record{Kind: KindRequest, ReqID: reqID, Path: PathEvent}, want: ErrInvalid},
		{name: "request without reqId", r: Record{N: 1, Kind: KindRequest, Path: PathEvent}, want: ErrInvalid},
		{name: "request outside the prefix", r: Record{N: 1, Kind: KindRequest, ReqID: reqID, Path: "/clair/ctl/status"}, want: ErrInvalid},
		{name: "request with a status", r: Record{N: 1, Kind: KindRequest, ReqID: reqID, Path: PathEvent, Status: 200}, want: ErrInvalid},
		{name: "response", r: Record{N: 1, Kind: KindResponse, ReqID: reqID, Status: 204}},
		{name: "response without reqId", r: Record{N: 1, Kind: KindResponse, Status: 204}, want: ErrInvalid},
		{name: "response with a silly status", r: Record{N: 1, Kind: KindResponse, ReqID: reqID, Status: 7}, want: ErrInvalid},
		{name: "response with a path", r: Record{N: 1, Kind: KindResponse, ReqID: reqID, Status: 204, Path: PathEvent}, want: ErrInvalid},
		{name: "known control", r: Record{N: 1, Kind: KindControl, Control: ControlRevoke}},
		{name: "cancel with reqId", r: Record{N: 1, Kind: KindControl, Control: ControlCancel, ReqID: reqID}},
		{name: "cancel without reqId", r: Record{N: 1, Kind: KindControl, Control: ControlCancel}, want: ErrInvalid},
		{name: "policy", r: Record{N: 1, Kind: KindControl, Control: ControlPolicy, Presence: &Presence{}}},
		{name: "policy without a body", r: Record{N: 1, Kind: KindControl, Control: ControlPolicy}},
		{name: "unknown control", r: Record{N: 1, Kind: KindControl, Control: "rekey"}, want: ErrInvalid},
		{name: "unknown kind", r: Record{N: 1, Kind: "ping"}, want: ErrInvalid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.r.Validate()
			if !errors.Is(err, tt.want) {
				t.Fatalf("Validate: err = %v, want %v", err, tt.want)
			}
			if tt.r.Control == "rekey" && !errors.As(err, &unknown) {
				t.Fatalf("Validate: err = %v, want an *UnknownControlError", err)
			}
		})
	}
}
