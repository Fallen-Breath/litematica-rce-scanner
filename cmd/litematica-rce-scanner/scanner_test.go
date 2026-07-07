package main

import (
	"archive/zip"
	"os"
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

func TestInspectGeneratedJars(t *testing.T) {
	tests := []struct {
		name       string
		classPath  string
		classBytes []byte
		manifest   string
		wantMod    string
		wantVer    string
		wantVuln   bool
	}{
		{
			name:       "vulnerable litematica",
			classPath:  litematicaSchematicBuffer,
			classBytes: testClassFile("(Ljava/lang/String;)V", "(Ljava/lang/String;I)V"),
			manifest:   `{"id":"litematica","version":"1.2.3"}`,
			wantMod:    "litematica",
			wantVer:    "1.2.3",
			wantVuln:   true,
		},
		{
			name:       "safe servux",
			classPath:  servuxSchematicBuffer,
			classBytes: testClassFile("(I)V"),
			manifest:   `{"id":"servux","version":"4.5.6"}`,
			wantMod:    "servux",
			wantVer:    "4.5.6",
			wantVuln:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jar := testJar(t, map[string][]byte{
				tt.classPath:    tt.classBytes,
				fabricModJSON:   []byte(tt.manifest),
				"unrelated.txt": []byte("ignored"),
			})

			findings, isJar, err := inspectZip(jar)
			if err != nil {
				t.Fatal(err)
			}
			if !isJar {
				t.Fatal("inspectZip did not recognize generated jar")
			}
			if len(findings) != 1 {
				t.Fatalf("findings count = %d, want 1", len(findings))
			}

			finding := findings[0]
			if finding.Error != "" {
				t.Fatalf("finding error: %s", finding.Error)
			}
			if finding.Mod != tt.wantMod || finding.Version != tt.wantVer || finding.Vulnerable != tt.wantVuln {
				t.Fatalf("finding = {mod:%q version:%q vulnerable:%v}, want {mod:%q version:%q vulnerable:%v}",
					finding.Mod, finding.Version, finding.Vulnerable, tt.wantMod, tt.wantVer, tt.wantVuln)
			}
		})
	}
}

func TestInspectZipIgnoresJarsWithoutTargetClass(t *testing.T) {
	jar := testJar(t, map[string][]byte{
		"fabric.mod.json": []byte(`{"version":"1.2.3"}`),
		"example.class":   testClassFile("(Ljava/lang/String;)V"),
	})

	findings, isJar, err := inspectZip(jar)
	if err != nil {
		t.Fatal(err)
	}
	if !isJar {
		t.Fatal("inspectZip did not recognize generated jar")
	}
	if len(findings) != 0 {
		t.Fatalf("findings count = %d, want 0", len(findings))
	}
}

func testJar(t *testing.T, entries map[string][]byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "sample.jar")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := zip.NewWriter(file)
	for name, data := range entries {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func testClassFile(constructors ...string) []byte {
	data := []byte{0xca, 0xfe, 0xba, 0xbe, 0x00, 0x00, 0x00, 0x3d}
	u2 := func(value uint16) {
		data = append(data, byte(value>>8), byte(value))
	}
	utf8 := func(value string) {
		data = append(data, 1)
		u2(uint16(len(value)))
		data = append(data, value...)
	}

	u2(uint16(2 + len(constructors)))
	utf8("<init>")
	for _, constructor := range constructors {
		utf8(constructor)
	}

	u2(0x0021)
	u2(1)
	u2(1)
	u2(0)
	u2(0)
	u2(uint16(len(constructors)))
	for i := range constructors {
		u2(0x0001)
		u2(1)
		u2(uint16(2 + i))
		u2(0)
	}
	return data
}
