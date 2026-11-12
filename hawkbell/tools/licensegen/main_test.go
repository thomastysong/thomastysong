package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const mitText = `MIT License

Copyright (c) 2026 Someone

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software ...`

const bsd2Text = `Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
* Redistributions of source code must retain the above copyright notice.`

const bsd3Text = bsd2Text + `
* Neither the name of the copyright holder nor the names of its
  contributors may be used to endorse or promote products derived from this software.`

func TestDetect(t *testing.T) {
	cases := []struct{ name, text, want string }{
		{"mit", mitText, "MIT"},
		{"bsd2", bsd2Text, "BSD-2-Clause"},
		{"bsd3", bsd3Text, "BSD-3-Clause"},
		{"apache body", "TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION", "Apache-2.0"},
		{"apache header", "Licensed under the Apache License, Version 2.0 (the \"License\");", "Apache-2.0"},
		{"dual", mitText + "\n" + "Licensed under the Apache License, Version 2.0", "Apache-2.0,MIT"},
		{"patents", "Additional IP Rights Grant (Patents)\n...", "patent-grant"},
		{"public domain", "All of the code has been dedicated to the public domain by the authors.", "public-domain"},
		{"mere mention is not a license", "This project is covered by two different licenses: MIT and Apache.", ""},
		{"url only", "https://example.org/logo.png\n", "reference"},
		{"wrapped lines", "Permission is hereby granted,\nfree of charge, to any person", "MIT"},
	}
	for _, c := range cases {
		if got := detect(c.text); got != c.want {
			t.Errorf("%s: detect = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestCheckReviewRefusesChangedText(t *testing.T) {
	rv := review{license: "MIT", files: map[string]string{"LICENSE": "MIT"}}
	if err := checkReview("m", rv, []licFile{{rel: "LICENSE", text: mitText}}); err != nil {
		t.Fatalf("matching text refused: %v", err)
	}
	// The module relicensed: the generator must stop, not rename.
	err := checkReview("m", rv, []licFile{{rel: "LICENSE", text: bsd3Text}})
	if err == nil || !strings.Contains(err.Error(), "read the text") {
		t.Fatalf("changed license not refused: %v", err)
	}
	// A new license file appeared.
	err = checkReview("m", rv, []licFile{{rel: "LICENSE", text: mitText}, {rel: "NOTICE", text: "x"}})
	if err == nil || !strings.Contains(err.Error(), "not in the reviewed table") {
		t.Fatalf("new license file not refused: %v", err)
	}
	// A reviewed file disappeared.
	rv2 := review{files: map[string]string{"LICENSE": "MIT", "PATENTS": "patent-grant"}}
	err = checkReview("m", rv2, []licFile{{rel: "LICENSE", text: mitText}})
	if err == nil || !strings.Contains(err.Error(), "was not found") {
		t.Fatalf("missing reviewed file not refused: %v", err)
	}
}

func TestLicenseFilesFailsWithoutLicense(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "sub", "pkg")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	m := &module{path: "example.com/m", version: "v1.0.0", dir: dir, pkgDirs: map[string]bool{pkg: true}}
	if _, err := licenseFiles(m); err == nil || !strings.Contains(err.Error(), "no license file") {
		t.Fatalf("module without license accepted: %v", err)
	}
	// A license only in a package directory does not make up for the root.
	if err := os.WriteFile(filepath.Join(pkg, "LICENSE"), []byte(mitText), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := licenseFiles(m); err == nil {
		t.Fatal("module with no root license accepted")
	}
	// Root plus nested: both are returned, root first.
	if err := os.WriteFile(filepath.Join(dir, "COPYING"), []byte(mitText), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := licenseFiles(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || files[0].rel != "COPYING" || files[1].rel != "sub/pkg/LICENSE" {
		t.Fatalf("files = %+v", files)
	}
}

func TestLinkedOn(t *testing.T) {
	all := map[string]bool{}
	for _, tg := range targets {
		all[tg[0]+"/"+tg[1]] = true
	}
	if got := linkedOn(all); got != "all release targets" {
		t.Errorf("all: %q", got)
	}
	if got := linkedOn(map[string]bool{"windows/amd64": true, "windows/arm64": true}); got != "windows only" {
		t.Errorf("windows: %q", got)
	}
	if got := linkedOn(map[string]bool{"darwin/arm64": true, "linux/amd64": true, "linux/arm64": true}); got != "linux, darwin/arm64 only" {
		t.Errorf("mixed: %q", got)
	}
}

func TestLicenseName(t *testing.T) {
	for _, n := range []string{"LICENSE", "LICENSE.txt", "LICENSE-3RD-PARTY.md", "COPYING", "NOTICE", "PATENTS", "licence"} {
		if !isLicenseName(n) {
			t.Errorf("%s not matched", n)
		}
	}
	for _, n := range []string{"README.md", "AUTHORS", "license_test.go", "licenses.go"} {
		if isLicenseName(n) {
			t.Errorf("%s matched", n)
		}
	}
}
