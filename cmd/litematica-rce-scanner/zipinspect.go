package main

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	litematicaSchematicBuffer = "fi/dy/masa/litematica/schematic/transmit/SchematicBuffer.class"
	servuxSchematicBuffer     = "fi/dy/masa/servux/schematic/transmit/SchematicBuffer.class"
	fabricModJSON             = "fabric.mod.json"
	maxClassFileSize          = 64 << 20
	maxFabricModJSONSize      = 1 << 20
)

func inspectZip(path string) ([]scanResult, bool, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false, err
	}
	if !info.Mode().IsRegular() || info.Size() < 22 {
		return nil, false, nil
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer file.Close()

	reader, err := zip.NewReader(file, info.Size())
	if err != nil {
		return nil, false, nil
	}

	var targets []*zip.File
	var manifest *zip.File
	for _, entry := range reader.File {
		if entry.Name == fabricModJSON {
			manifest = entry
		}
		if _, ok := targetMod(entry.Name); ok {
			targets = append(targets, entry)
		}
	}
	if len(targets) == 0 {
		return nil, true, nil
	}

	modVersion := ""
	if manifest != nil {
		modVersion, _ = readFabricModVersion(manifest)
	}

	findings := make([]scanResult, 0, len(targets))
	for _, entry := range targets {
		findings = append(findings, inspectClassEntry(path, entry, modVersion))
	}
	return findings, true, nil
}

func inspectClassEntry(path string, entry *zip.File, modVersion string) scanResult {
	mod, _ := targetMod(entry.Name)
	result := scanResult{
		Path:    path,
		Mod:     mod,
		Version: modVersion,
	}

	data, err := readZipEntry(entry, maxClassFileSize)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	constructors, err := parseConstructors(data)
	if err != nil {
		result.Error = err.Error()
		return result
	}

	result.Vulnerable = allConstructorsStartWithString(constructors)
	return result
}

func readFabricModVersion(entry *zip.File) (string, error) {
	data, err := readZipEntry(entry, maxFabricModJSONSize)
	if err != nil {
		return "", err
	}

	var manifest map[string]json.RawMessage
	if err := json.Unmarshal(data, &manifest); err != nil {
		return "", err
	}
	rawVersion, ok := manifest["version"]
	if !ok {
		return "", nil
	}

	var modVersion string
	if err := json.Unmarshal(rawVersion, &modVersion); err != nil {
		return "", nil
	}
	return strings.TrimSpace(modVersion), nil
}

func readZipEntry(entry *zip.File, limit int64) ([]byte, error) {
	if entry.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("zip entry is too large: %d bytes", entry.UncompressedSize64)
	}
	reader, err := entry.Open()
	if err != nil {
		return nil, err
	}

	limited := &io.LimitedReader{R: reader, N: limit + 1}
	data, readErr := io.ReadAll(limited)
	closeErr := reader.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("zip entry exceeds %d bytes", limit)
	}
	return data, nil
}

func targetMod(name string) (string, bool) {
	switch name {
	case litematicaSchematicBuffer:
		return "litematica", true
	case servuxSchematicBuffer:
		return "servux", true
	default:
		return "", false
	}
}
