package ojson

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRoundTripKeepsOrderAndForm(t *testing.T) {
	t.Parallel()

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			t.Parallel()
			want, err := os.ReadFile(filepath.Join("testdata", e.Name()))
			if err != nil {
				t.Fatal(err)
			}
			v, err := ParseBytes(want)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got, err := Marshal(v, "  ")
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if string(got)+"\n" != string(want) {
				t.Fatalf("round trip changed the file:\n%s\nwant\n%s", got, want)
			}
		})
	}
}

func TestObjectOperations(t *testing.T) {
	t.Parallel()

	v, err := ParseBytes([]byte(`{"b":1,"a":2,"b":3}`))
	if err != nil {
		t.Fatal(err)
	}
	obj := AsObject(v)
	if obj == nil {
		t.Fatal("not an object")
	}
	if keys := obj.Keys(); len(keys) != 2 || keys[0] != "b" || keys[1] != "a" {
		t.Errorf("keys = %v, want [b a] (duplicate keeps its first position)", keys)
	}
	if b, _ := obj.Get("b"); b != json.Number("3") {
		t.Errorf("b = %v, want 3 (last value wins)", b)
	}
	obj.Set("c", "x")
	obj.Set("b", true)
	obj.Delete("a")
	obj.Delete("missing")
	got, _ := Marshal(obj, "")
	if string(got) != `{"b":true,"c":"x"}` {
		t.Errorf("Marshal = %s", got)
	}
	if obj.Len() != 2 {
		t.Errorf("Len = %d", obj.Len())
	}
}

func TestMarshalForms(t *testing.T) {
	t.Parallel()

	v, err := ParseBytes([]byte(`{"s":"a > b & \"c\" é","n":1.50,"e":{},"l":[],"nested":[{"x":null},[true,false]]}`))
	if err != nil {
		t.Fatal(err)
	}
	compact, _ := Marshal(v, "")
	if want := `{"s":"a > b & \"c\" é","n":1.50,"e":{},"l":[],"nested":[{"x":null},[true,false]]}`; string(compact) != want {
		t.Errorf("compact = %s\nwant      %s", compact, want)
	}
	pretty, _ := Marshal(v, "  ")
	want := "{\n  \"s\": \"a > b & \\\"c\\\" é\",\n  \"n\": 1.50,\n  \"e\": {},\n  \"l\": [],\n  \"nested\": [\n    {\n      \"x\": null\n    },\n    [\n      true,\n      false\n    ]\n  ]\n}"
	if string(pretty) != want {
		t.Errorf("pretty =\n%s\nwant\n%s", pretty, want)
	}
	var sb strings.Builder
	if err := Write(&sb, v, ""); err != nil || !strings.HasSuffix(sb.String(), "}\n") {
		t.Errorf("Write = %q, %v", sb.String(), err)
	}
}

func TestParseRejects(t *testing.T) {
	t.Parallel()

	for _, in := range []string{``, `{`, `{"a":1} x`, `[1,]`, `{1:2}`, `nope`} {
		if _, err := ParseBytes([]byte(in)); err == nil {
			t.Errorf("Parse(%q): want an error", in)
		}
	}
	if _, err := Marshal(struct{}{}, ""); err == nil {
		t.Error("Marshal of a struct: want an error")
	}
}

func TestAccessors(t *testing.T) {
	t.Parallel()

	v, _ := ParseBytes([]byte(`{"a":[1],"s":"x"}`))
	obj := AsObject(v)
	a, _ := obj.Get("a")
	s, _ := obj.Get("s")
	if AsArray(a) == nil || AsArray(s) != nil || AsString(s) != "x" || AsString(a) != "" || AsObject(s) != nil {
		t.Error("accessors disagree with the values")
	}
	raw, err := FromRaw(json.RawMessage(`{"k":true}`))
	if err != nil || AsObject(raw) == nil {
		t.Errorf("FromRaw = %v, %v", raw, err)
	}
}
