package caseflow

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type ReportData struct {
	Title         string
	Case          *Case
	Device        map[string]any
	APKPaths      []string
	Current       map[string]string
	PID           int
	Screenshots   []string
	UIXML         []string
	Logcat        []string
	FridaScript   string
	FridaSession  any
	FridaMessages []string
	Bypass        map[string]any
	Findings      []string
}

func GenerateReport(path string, d ReportData) error {
	var b strings.Builder
	b.WriteString("# " + d.Title + "\n\n")
	b.WriteString(fmt.Sprintf("- Generated: `%s`\n", time.Now().UTC().Format(time.RFC3339)))
	if d.Case != nil {
		b.WriteString(fmt.Sprintf("- Case ID: `%s`\n- Package: `%s`\n- Case Dir: `%s`\n", d.Case.ID, d.Case.PackageName, d.Case.Root))
	}
	b.WriteString("\n## Scope and Authorization\n\n")
	b.WriteString("This report is generated for authorized Android security research on CTF, lab, self-owned, or explicitly permitted apps. High-risk runtime actions require `confirm=true`.\n\n")

	b.WriteString("## Device\n\n")
	b.WriteString(fenceJSON(d.Device))

	b.WriteString("\n## APK and Package Artifacts\n\n")
	for _, p := range d.APKPaths {
		b.WriteString("- `" + p + "`\n")
	}
	b.WriteString("\n")

	b.WriteString("## Runtime State\n\n")
	b.WriteString(fmt.Sprintf("- Current Activity: `%s`\n- Foreground Package: `%s`\n- PID: `%d`\n\n", d.Current["component"], d.Current["packageName"], d.PID))

	b.WriteString("## Screenshots\n\n")
	for _, p := range d.Screenshots {
		b.WriteString("- `" + p + "`\n")
	}
	b.WriteString("\n## UI XML\n\n")
	for _, p := range d.UIXML {
		b.WriteString("- `" + p + "`\n")
	}

	b.WriteString("\n## Logcat Snapshot\n\n")
	b.WriteString("```text\n")
	max := len(d.Logcat)
	if max > 300 {
		max = 300
	}
	for _, l := range d.Logcat[:max] {
		b.WriteString(l + "\n")
	}
	if len(d.Logcat) > max {
		b.WriteString("...[truncated]\n")
	}
	b.WriteString("```\n\n")

	b.WriteString("## Frida Observation\n\n")
	if d.FridaScript != "" {
		b.WriteString("- Script: `" + d.FridaScript + "`\n")
	}
	b.WriteString("- Session: " + fenceJSONInline(d.FridaSession) + "\n\n")
	b.WriteString("```text\n")
	for _, m := range d.FridaMessages {
		b.WriteString(m + "\n")
	}
	b.WriteString("```\n\n")

	b.WriteString("## CTF Bypass Mode\n\n")
	if d.Bypass == nil || len(d.Bypass) == 0 {
		b.WriteString("Bypass mode was not enabled for this run.\n\n")
	} else {
		b.WriteString("The section records target-scoped CTF/lab runtime profile information: detection points, selected profile(s), scope, load time, and revert state.\n\n")
		b.WriteString(fenceJSON(d.Bypass))
	}

	b.WriteString("\n## Findings Summary\n\n")
	if len(d.Findings) == 0 {
		b.WriteString("- No findings were automatically asserted; review artifacts manually.\n")
	}
	for _, f := range d.Findings {
		b.WriteString("- " + f + "\n")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(b.String()), 0600)
}

func fenceJSON(v any) string { return "```json\n" + fenceJSONInline(v) + "\n```\n" }
func fenceJSONInline(v any) string {
	if v == nil {
		return "null"
	}
	b, _ := jsonMarshalIndent(v)
	return string(b)
}
