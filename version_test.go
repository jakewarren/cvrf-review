package main

import "testing"

func TestIsFullVersion(t *testing.T) {
    tests := []struct {
        in   string
        want bool
    }{
        {"6.4.2", true},
        {"7.0.14", true},
        {"0.0.1", true},
        {"10.12.0", true},
        {" 7.0.14 ", true}, // leading/trailing spaces are trimmed
        {"", false},
        {"7", false},
        {"7.0", false},
        {"7.0.", false},
        {"7..0", false},
        {"a.b.c", false},
        {"7.0.14.1", false},
        {"7.0.14-beta", false},
    }

    for _, tt := range tests {
        got := isFullVersion(tt.in)
        if got != tt.want {
            t.Fatalf("isFullVersion(%q) = %v, want %v", tt.in, got, tt.want)
        }
    }
}

