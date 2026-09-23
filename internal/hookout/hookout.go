// Package hookout checks what a phone answers to a held decide against the
// PermissionRequest it answers, and rebuilds the answer from the fields a
// phone may set (ADR 2026-09.w4ww). A paired phone may allow or deny the
// prompt it was shown; it must not rewrite the tool call, grant itself
// standing rules, or steer the session through the hook output's other
// fields (ADR 2026-09.3gre's threat model, one hop later).
//
// The shapes are the phone's HookOutput (clair `:shared`, hooks/HookOutput.kt):
// allow, with the request's own permission suggestions echoed; deny, with a
// message and interrupt; ExitPlanMode's allow, with the tool input minus what
// Claude Code injected and a session setMode; AskUserQuestion's allow, with
// the tool input plus `answers`.
package hookout

import (
	"errors"
	"fmt"

	"claircode.app/clair-agent/internal/ojson"
)

// ErrRefused is an answer that does not fit the request it answers; the
// caller answers "no decision" instead.
var ErrRefused = errors.New("hookout: answer refused")

// Claude Code's names, as the phone's ClaudeCodeHooks spells them.
const (
	eventPermissionRequest = "PermissionRequest"
	toolAskUserQuestion    = "AskUserQuestion"
	toolExitPlanMode       = "ExitPlanMode"
	behaviorAllow          = "allow"
	behaviorDeny           = "deny"
	keyAnswers             = "answers"
	destinationSession     = "session"
)

// planModes are the modes an ExitPlanMode approval may switch the session
// to when Claude Code suggested none: the terminal dialog's three approve
// rows, which the phone mirrors (HookOutput.plan).
var planModes = map[string]bool{"default": true, "acceptEdits": true, "auto": true}

// request is what the check reads of a PermissionRequest: the event, the
// tool, its input and Claude Code's suggestions — nothing else, and nothing
// of it is logged.
type request struct {
	tool        string
	input       *ojson.Object
	suggestions []ojson.Value
}

// Check returns the hook output to hand Claude Code for a phone's answer to
// a held request, rebuilt from the fields the request allows, or an error
// wrapping ErrRefused. The error names the rule, never a value.
func Check(requestBody, answerBody []byte) ([]byte, error) {
	req, err := parseRequest(requestBody)
	if err != nil {
		return nil, err
	}
	v, err := ojson.ParseBytes(answerBody)
	if err != nil {
		return nil, fmt.Errorf("%w: answer is not JSON", ErrRefused)
	}
	specific := ojson.AsObject(member(ojson.AsObject(v), "hookSpecificOutput"))
	if specific == nil {
		return nil, fmt.Errorf("%w: no hookSpecificOutput", ErrRefused)
	}
	if ev, _ := specific.Get("hookEventName"); ev != eventPermissionRequest {
		return nil, fmt.Errorf("%w: hookEventName is not %s", ErrRefused, eventPermissionRequest)
	}
	in := ojson.AsObject(member(specific, "decision"))
	if in == nil {
		return nil, fmt.Errorf("%w: no decision", ErrRefused)
	}
	out := ojson.NewObject()
	switch behavior, _ := in.Get("behavior"); behavior {
	case behaviorAllow:
		out.Set("behavior", behaviorAllow)
		if err = req.allow(in, out); err != nil {
			return nil, err
		}
	case behaviorDeny:
		out.Set("behavior", behaviorDeny)
		if err = deny(in, out); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: behavior is neither allow nor deny", ErrRefused)
	}
	rebuilt := ojson.NewObject()
	rebuilt.Set("hookEventName", eventPermissionRequest)
	rebuilt.Set("decision", out)
	top := ojson.NewObject()
	top.Set("hookSpecificOutput", rebuilt)
	data, err := ojson.Marshal(top, "")
	if err != nil {
		return nil, fmt.Errorf("hookout: encode: %w", err)
	}
	return data, nil
}

func parseRequest(body []byte) (request, error) {
	v, err := ojson.ParseBytes(body)
	top := ojson.AsObject(v)
	if err != nil || top == nil {
		return request{}, fmt.Errorf("%w: request is not a JSON object", ErrRefused)
	}
	// Only a PermissionRequest is answered with a decision; any other event
	// routed to decide is fire-and-forget as far as the phone is concerned.
	if ev, _ := top.Get("hook_event_name"); ev != eventPermissionRequest {
		return request{}, fmt.Errorf("%w: request is not a %s", ErrRefused, eventPermissionRequest)
	}
	input := ojson.AsObject(member(top, "tool_input"))
	if input == nil {
		input = ojson.NewObject()
	}
	return request{
		tool:        ojson.AsString(member(top, "tool_name")),
		input:       input,
		suggestions: ojson.AsArray(member(top, "permission_suggestions")),
	}, nil
}

// allow carries updatedInput and updatedPermissions over when the request
// allows them; message and interrupt mean nothing on an allow and are dropped.
func (r request) allow(in, out *ojson.Object) error {
	if updated, ok := in.Get("updatedInput"); ok {
		obj := ojson.AsObject(updated)
		if obj == nil {
			return fmt.Errorf("%w: updatedInput is not an object", ErrRefused)
		}
		if err := r.checkInput(obj); err != nil {
			return err
		}
		out.Set("updatedInput", obj)
	}
	if perms, ok := in.Get("updatedPermissions"); ok {
		entries, isArray := perms.([]ojson.Value)
		if !isArray {
			return fmt.Errorf("%w: updatedPermissions is not an array", ErrRefused)
		}
		for _, e := range entries {
			if !r.permitted(e) {
				return fmt.Errorf("%w: updatedPermissions entry is not one the request suggested", ErrRefused)
			}
		}
		if len(entries) > 0 {
			out.Set("updatedPermissions", entries)
		}
	}
	return nil
}

// checkInput allows a changed tool input for the two tools whose answer is
// carried in it, and only in the shape the phone writes.
func (r request) checkInput(updated *ojson.Object) error {
	switch r.tool {
	case toolAskUserQuestion:
		// The original input, questions included, with `answers` set to
		// question text → the chosen label(s): the answers are the user's
		// words, the questions are not the phone's to change.
		if !ojson.Equal(without(updated, keyAnswers), without(r.input, keyAnswers)) {
			return fmt.Errorf("%w: updatedInput changes the questions", ErrRefused)
		}
		answers, ok := updated.Get(keyAnswers)
		if !ok {
			return nil
		}
		obj := ojson.AsObject(answers)
		if obj == nil {
			return fmt.Errorf("%w: answers is not an object", ErrRefused)
		}
		for _, k := range obj.Keys() {
			if v, _ := obj.Get(k); !isString(v) {
				return fmt.Errorf("%w: an answer is not a string", ErrRefused)
			}
		}
		return nil
	case toolExitPlanMode:
		// The original input minus the plan Claude Code injected: a subset,
		// never a new or changed member.
		for _, k := range updated.Keys() {
			orig, ok := r.input.Get(k)
			if v, _ := updated.Get(k); !ok || !ojson.Equal(v, orig) {
				return fmt.Errorf("%w: updatedInput is not a subset of the plan's input", ErrRefused)
			}
		}
		return nil
	default:
		return fmt.Errorf("%w: updatedInput for a tool whose input the phone may not change", ErrRefused)
	}
}

// permitted reports whether an updatedPermissions entry is one of Claude
// Code's own suggestions for this request, or the session setMode an
// ExitPlanMode approval writes when Claude Code suggested none.
func (r request) permitted(entry ojson.Value) bool {
	for _, s := range r.suggestions {
		if ojson.Equal(entry, s) {
			return true
		}
	}
	if r.tool != toolExitPlanMode {
		return false
	}
	obj := ojson.AsObject(entry)
	if obj == nil || obj.Len() != 3 {
		return false
	}
	typ, _ := obj.Get("type")
	mode, _ := obj.Get("mode")
	dest, _ := obj.Get("destination")
	m, ok := mode.(string)
	return typ == "setMode" && ok && planModes[m] && dest == destinationSession
}

// deny carries message and interrupt over, and nothing else.
func deny(in, out *ojson.Object) error {
	if msg, ok := in.Get("message"); ok {
		if !isString(msg) {
			return fmt.Errorf("%w: message is not a string", ErrRefused)
		}
		out.Set("message", msg)
	}
	if interrupt, ok := in.Get("interrupt"); ok {
		if _, isBool := interrupt.(bool); !isBool {
			return fmt.Errorf("%w: interrupt is not a boolean", ErrRefused)
		}
		out.Set("interrupt", interrupt)
	}
	return nil
}

// member returns obj[key], or nil when obj is nil or has no such member.
func member(obj *ojson.Object, key string) ojson.Value {
	if obj == nil {
		return nil
	}
	v, _ := obj.Get(key)
	return v
}

// without is a copy of obj minus one member.
func without(obj *ojson.Object, key string) *ojson.Object {
	c := ojson.NewObject()
	for _, k := range obj.Keys() {
		if k != key {
			v, _ := obj.Get(k)
			c.Set(k, v)
		}
	}
	return c
}

func isString(v ojson.Value) bool {
	_, ok := v.(string)
	return ok
}
