package main

import (
	"path/filepath"
	"testing"
)

func TestFirstParameterIsJavaLangString(t *testing.T) {
	tests := []struct {
		name       string
		descriptor string
		want       bool
	}{
		{name: "string only", descriptor: "(Ljava/lang/String;)V", want: true},
		{name: "string first", descriptor: "(Ljava/lang/String;I)V", want: true},
		{name: "int first", descriptor: "(ILjava/lang/String;)V", want: false},
		{name: "no args", descriptor: "()V", want: false},
		{name: "string array first", descriptor: "([Ljava/lang/String;)V", want: false},
		{name: "malformed", descriptor: "Ljava/lang/String;)V", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firstParameterIsJavaLangString(tt.descriptor); got != tt.want {
				t.Fatalf("firstParameterIsJavaLangString(%q) = %v, want %v", tt.descriptor, got, tt.want)
			}
		})
	}
}

func TestInspectZipFixtures(t *testing.T) {
	safe, vulnerable, errors := inspectFixtureDir(t, "../../testdata/fixed")
	if safe != 8 || vulnerable != 0 || errors != 0 {
		t.Fatalf("fixed fixtures: safe=%d vulnerable=%d errors=%d, want safe=8 vulnerable=0 errors=0", safe, vulnerable, errors)
	}

	safe, vulnerable, errors = inspectFixtureDir(t, "../../testdata/vulnerable")
	if safe != 0 || vulnerable != 15 || errors != 0 {
		t.Fatalf("vulnerable fixtures: safe=%d vulnerable=%d errors=%d, want safe=0 vulnerable=15 errors=0", safe, vulnerable, errors)
	}
}

func inspectFixtureDir(t *testing.T, dir string) (safe int, vulnerable int, errors int) {
	t.Helper()

	paths, err := filepath.Glob(filepath.Join(dir, "*.jar*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatalf("no fixture jars found in %s", dir)
	}

	for _, path := range paths {
		findings, _, err := inspectZip(path)
		if err != nil {
			t.Fatalf("inspectZip(%q): %v", path, err)
		}
		for _, finding := range findings {
			if finding.Error != "" {
				errors++
				continue
			}
			if finding.Vulnerable {
				vulnerable++
			} else {
				safe++
			}
		}
	}
	return safe, vulnerable, errors
}
