// Command winres writes the Windows resources — icon and version information
// — that build-release.sh embeds in dtp-agent.exe and dtp-agent-tray.exe.
//
//	go run ./script/winres <version> <out-dir>
//
// It writes the icon images, drawn by the same code as the notification-area
// icon (internal/tray), and one go-winres configuration per binary. The images
// are generated rather than committed, so the only artwork in the repository
// is the pinwheel's path data, which a reviewer can read.
package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/SSLcom/dtp-discovery-agent/internal/tray"
)

// Every size Windows asks a file icon for, from the 16 px of a details list to
// the 256 px of "extra large icons".
var sizes = []int{16, 20, 24, 32, 40, 48, 64, 256}

type executable struct{ file, description string }

var binaries = []executable{
	{"dtp-agent.exe", "DTP certificate discovery agent"},
	{"dtp-agent-tray.exe", "DTP certificate discovery agent: notification-area icon"},
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: winres <version> <out-dir>")
		os.Exit(2)
	}
	version, out := strings.TrimPrefix(os.Args[1], "v"), os.Args[2]
	if err := os.MkdirAll(out, 0o755); err != nil {
		fail(err)
	}

	var icons []string
	for _, size := range sizes {
		name := fmt.Sprintf("icon-%d.png", size)
		if err := os.WriteFile(filepath.Join(out, name), tray.AppIcon(size), 0o644); err != nil {
			fail(err)
		}
		icons = append(icons, name)
	}

	// The same images as one .ico, for the installer: Add/Remove Programs
	// shows an icon file, not an executable's resource. PNG-in-ICO entries,
	// which every supported Windows reads.
	if err := writeICO(filepath.Join(out, "pinwheel.ico"), out, icons); err != nil {
		fail(err)
	}

	// The fixed version is four numbers; a prerelease such as 0.0.0-ci keeps
	// its numeric part there and its full name in the strings.
	numeric := regexp.MustCompile(`^\d+(\.\d+){0,3}`).FindString(version)
	for len(strings.Split(numeric, ".")) < 4 {
		if numeric == "" {
			numeric = "0"
			continue
		}
		numeric += ".0"
	}

	for _, b := range binaries {
		cfg := map[string]any{
			"RT_GROUP_ICON": map[string]any{"APP": map[string]any{"0000": icons}},
			// NO RT_MANIFEST, deliberately. A manifest would set DPI awareness
			// and other process-wide behaviour that the tray sets in code
			// (SetProcessDpiAwarenessContext), and a manifest that disagreed
			// would make that call fail. Icon and version only.
			"RT_VERSION": map[string]any{"#1": map[string]any{"0000": map[string]any{
				"fixed": map[string]any{"file_version": numeric, "product_version": numeric},
				"info": map[string]any{"0409": map[string]any{
					"CompanyName":      "SSL.com",
					"FileDescription":  b.description,
					"FileVersion":      version,
					"InternalName":     strings.TrimSuffix(b.file, ".exe"),
					"LegalCopyright":   "SSL.com",
					"OriginalFilename": b.file,
					"ProductName":      "DTP Certificate Discovery Agent",
					"ProductVersion":   version,
				}},
			}}},
		}
		raw, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			fail(err)
		}
		name := strings.TrimSuffix(b.file, ".exe") + ".json"
		if err := os.WriteFile(filepath.Join(out, name), append(raw, '\n'), 0o644); err != nil {
			fail(err)
		}
	}
}

// writeICO packs PNG images into an .ico: a six-byte header, one sixteen-byte
// entry per image, then the images. A width or height of 256 is written as 0.
func writeICO(path, dir string, names []string) error {
	var images [][]byte
	for _, n := range names {
		raw, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			return err
		}
		images = append(images, raw)
	}
	var buf bytes.Buffer
	le := binary.LittleEndian
	_ = binary.Write(&buf, le, [3]uint16{0, 1, uint16(len(images))})
	offset := 6 + 16*len(images)
	for i, img := range images {
		dim := byte(sizes[i])
		if sizes[i] >= 256 {
			dim = 0
		}
		buf.Write([]byte{dim, dim, 0, 0})
		_ = binary.Write(&buf, le, [2]uint16{1, 32})
		_ = binary.Write(&buf, le, [2]uint32{uint32(len(img)), uint32(offset)})
		offset += len(img)
	}
	for _, img := range images {
		buf.Write(img)
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "winres:", err)
	os.Exit(1)
}
