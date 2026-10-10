package engine

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestBracketDepth(t *testing.T) {
	cases := map[string]int{
		"":                        0,
		"a = 1":                   0,
		"a = (1)":                 1,
		"a = [{ b = (1) }]":       3,
		"a = ))) (":               1,
		"a = \"${x}\"":            1,
		"resource \"x\" \"y\" {}": 1,
	}
	for in, want := range cases {
		if got := BracketDepth([]byte(in), MaxNestingDepth); got != want {
			t.Errorf("%q: depth %d, want %d", in, got, want)
		}
	}
	// A hostile input stops at limit+1 and runs in linear time.
	start := time.Now()
	deep := bytes.Repeat([]byte("("), 1<<20)
	if got := BracketDepth(deep, 100); got != 101 {
		t.Fatalf("clamped depth %d", got)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("slow: %s", time.Since(start))
	}
}

func TestYAMLDepth(t *testing.T) {
	cases := map[string]int{
		"":                        0,
		"a: 1\nb: 2\n":            0,
		"a: [1, 2]\n":             1,
		"a: {b: [1, {c: 2}]}\n":   3,
		"a:\n  - 1\n  - 2\n":      1,
		"a:\n  - - - x\n":         3,
		"? ? k\n: v\n":            2,
		"a: [\n  1,\n  [2]\n]\n":  2,
		"a:\n  - [1, {b: [2]}]\n": 4,
		"spec: ]]]] [\n":          1,
		"# comment [ [ [\nx: 1\n": 3, // over-approximation: comments count
	}
	for in, want := range cases {
		if got := YAMLDepth([]byte(in), MaxNestingDepth); got != want {
			t.Errorf("%q: depth %d, want %d", in, got, want)
		}
	}
	start := time.Now()
	for _, hostile := range [][]byte{
		bytes.Repeat([]byte("["), 5<<20),
		[]byte("spec:\n  " + strings.Repeat("- ", 1<<19) + "x\n"),
		[]byte(strings.Repeat("- ? ", 1<<18) + "x\n"),
	} {
		if got := YAMLDepth(hostile, 100); got != 101 {
			t.Fatalf("clamped depth %d", got)
		}
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("slow: %s", time.Since(start))
	}
}

func FuzzDepth(f *testing.F) {
	f.Add([]byte("a = ((1))"))
	f.Add([]byte("a:\n  - - [1, {b: 2}]\n"))
	f.Add(bytes.Repeat([]byte("["), 1000))
	f.Fuzz(func(t *testing.T, b []byte) {
		if d := BracketDepth(b, 50); d > 51 || d < 0 {
			t.Fatalf("bracket depth %d out of range", d)
		}
		if d := YAMLDepth(b, 50); d > 51 || d < 0 {
			t.Fatalf("yaml depth %d out of range", d)
		}
	})
}
