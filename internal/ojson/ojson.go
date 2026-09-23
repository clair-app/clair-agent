// Package ojson is an order-preserving JSON object model for editing files
// people own, such as Claude Code's settings.json: a round trip keeps every
// key where it was, numbers as written, and unicode as unicode. The standard
// encoding/json sorts map keys and encoding/json/v2 is still behind a
// GOEXPERIMENT in Go 1.26, so this is a small decoder over json.Decoder's
// tokens and a matching writer.
package ojson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Value is a JSON value: *Object, []Value, string, json.Number, bool or nil.
type Value = any

// Object is a JSON object whose keys keep their order.
type Object struct {
	keys   []string
	values map[string]Value
}

// NewObject makes an empty object.
func NewObject() *Object {
	return &Object{values: make(map[string]Value)}
}

// Get returns a member.
func (o *Object) Get(key string) (Value, bool) {
	v, ok := o.values[key]
	return v, ok
}

// Set replaces a member in place, or appends a new one.
func (o *Object) Set(key string, v Value) {
	if _, ok := o.values[key]; !ok {
		o.keys = append(o.keys, key)
	}
	o.values[key] = v
}

// Delete removes a member.
func (o *Object) Delete(key string) {
	if _, ok := o.values[key]; !ok {
		return
	}
	delete(o.values, key)
	o.keys = slices.DeleteFunc(o.keys, func(k string) bool { return k == key })
}

// Keys lists the members in order.
func (o *Object) Keys() []string { return slices.Clone(o.keys) }

// Len is the number of members.
func (o *Object) Len() int { return len(o.keys) }

// MaxDepth bounds how deeply objects and arrays may nest. Claude Code's
// settings nest a few levels; a deeper document is refused rather than
// recursed into, and re-indented, level by level.
const MaxDepth = 64

// Parse reads one JSON value; trailing data is an error, and so is nesting
// deeper than MaxDepth. A duplicate key keeps its first position and its
// last value.
func Parse(r io.Reader) (Value, error) {
	dec := json.NewDecoder(r)
	dec.UseNumber()
	v, err := parseValue(dec, 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("ojson: data after the top-level value")
	}
	return v, nil
}

// ParseBytes is Parse over a byte slice.
func ParseBytes(b []byte) (Value, error) {
	return Parse(bytes.NewReader(b))
}

func parseValue(dec *json.Decoder, depth int) (Value, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("ojson: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if depth >= MaxDepth {
			return nil, fmt.Errorf("ojson: nested deeper than %d", MaxDepth)
		}
		switch t {
		case '{':
			obj := NewObject()
			for dec.More() {
				keyTok, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("ojson: %w", err)
				}
				key, ok := keyTok.(string)
				if !ok {
					return nil, fmt.Errorf("ojson: object key %v is not a string", keyTok)
				}
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				obj.Set(key, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("ojson: %w", err)
			}
			return obj, nil
		case '[':
			arr := []Value{}
			for dec.More() {
				val, err := parseValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, val)
			}
			if _, err := dec.Token(); err != nil {
				return nil, fmt.Errorf("ojson: %w", err)
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("ojson: unexpected %v", t)
		}
	case string, json.Number, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("ojson: unexpected token %T", tok)
	}
}

// Marshal renders a value. An empty indent gives the compact form; otherwise
// members are one per line, nested by indent, with `": "` after keys and
// empty containers as `{}` / `[]` — what Python's json.dump(indent=2) and
// Claude Code itself write. Strings keep their unicode and are not HTML
// escaped.
func Marshal(v Value, indent string) ([]byte, error) {
	var buf bytes.Buffer
	if err := encode(&buf, v, indent, 0); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Write renders a value followed by a newline.
func Write(w io.Writer, v Value, indent string) error {
	data, err := Marshal(v, indent)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		return fmt.Errorf("ojson: write: %w", err)
	}
	return nil
}

func encode(buf *bytes.Buffer, v Value, indent string, depth int) error {
	newline := func(d int) {
		if indent != "" {
			buf.WriteByte('\n')
			buf.WriteString(strings.Repeat(indent, d))
		}
	}
	switch t := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if t {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(t.String())
	case string:
		writeString(buf, t)
	case []Value:
		if len(t) == 0 {
			buf.WriteString("[]")
			return nil
		}
		buf.WriteByte('[')
		for i, item := range t {
			if i > 0 {
				buf.WriteByte(',')
			}
			newline(depth + 1)
			if err := encode(buf, item, indent, depth+1); err != nil {
				return err
			}
		}
		newline(depth)
		buf.WriteByte(']')
	case *Object:
		if t == nil || t.Len() == 0 {
			buf.WriteString("{}")
			return nil
		}
		buf.WriteByte('{')
		for i, key := range t.keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			newline(depth + 1)
			writeString(buf, key)
			buf.WriteByte(':')
			if indent != "" {
				buf.WriteByte(' ')
			}
			if err := encode(buf, t.values[key], indent, depth+1); err != nil {
				return err
			}
		}
		newline(depth)
		buf.WriteByte('}')
	default:
		return fmt.Errorf("ojson: cannot encode %T", v)
	}
	return nil
}

// writeString quotes a string as JSON without HTML escaping.
func writeString(buf *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		// A Go string always encodes; invalid UTF-8 is replaced, not refused.
		panic("ojson: encode string: " + err.Error())
	}
	buf.Write(bytes.TrimSuffix(tmp.Bytes(), []byte("\n")))
}

// FromRaw parses a json.RawMessage into the model.
func FromRaw(raw json.RawMessage) (Value, error) {
	return ParseBytes(raw)
}

// AsObject returns v as an *Object, or nil when it is not one.
func AsObject(v Value) *Object {
	obj, ok := v.(*Object)
	if !ok {
		return nil
	}
	return obj
}

// AsArray returns v as a []Value, or nil when it is not one.
func AsArray(v Value) []Value {
	arr, ok := v.([]Value)
	if !ok {
		return nil
	}
	return arr
}

// AsString returns v as a string, or "" when it is not one.
func AsString(v Value) string {
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// Equal reports whether two values are the same JSON: objects compare as
// sets of members, whatever their order; arrays element by element; numbers
// by their literal, which is what a peer that echoes a value sends back.
func Equal(a, b Value) bool {
	switch x := a.(type) {
	case *Object:
		y, ok := b.(*Object)
		if !ok || x.Len() != y.Len() {
			return false
		}
		for _, k := range x.keys {
			yv, ok := y.Get(k)
			if !ok || !Equal(x.values[k], yv) {
				return false
			}
		}
		return true
	case []Value:
		y, ok := b.([]Value)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !Equal(x[i], y[i]) {
				return false
			}
		}
		return true
	case string, json.Number, bool, nil:
		return a == b
	default:
		return false
	}
}
