package safety

import (
	"archive/zip"
	"bytes"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type BypassProfile struct {
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	Scope           string         `json:"scope"`
	AllowedUse      string         `json:"allowedUse"`
	Protections     []string       `json:"protections"`
	RequiresConfirm bool           `json:"requiresConfirm"`
	Actions         []BypassAction `json:"actions"`
	Revert          []BypassAction `json:"revert"`
}

type BypassAction struct {
	Type        string         `json:"type"`
	Description string         `json:"description,omitempty"`
	ClassName   string         `json:"className,omitempty"`
	MethodName  string         `json:"methodName,omitempty"`
	ReturnType  string         `json:"returnType,omitempty"`
	ReturnValue any            `json:"returnValue,omitempty"`
	Match       string         `json:"match,omitempty"`
	Script      string         `json:"script,omitempty"`
	Args        map[string]any `json:"args,omitempty"`
}

type DetectionPoint struct {
	Protection   string   `json:"protection"`
	Source       string   `json:"source"`
	Keyword      string   `json:"keyword,omitempty"` // backward-compatible primary keyword
	Keywords     []string `json:"keywords,omitempty"`
	Category     string   `json:"category,omitempty"`
	Rule         string   `json:"rule,omitempty"`
	Evidence     string   `json:"evidence,omitempty"`
	EvidenceList []string `json:"evidenceList,omitempty"`
	Score        int      `json:"score"`
	Confidence   string   `json:"confidence"`
	Reason       string   `json:"reason,omitempty"`
}

type Classification struct {
	Protection string `json:"protection"`
	Level      string `json:"level"`
	Count      int    `json:"count"`
	Score      int    `json:"score"`
	Summary    string `json:"summary"`
}

type BypassPlan struct {
	PackageName       string           `json:"packageName"`
	GeneratedAt       time.Time        `json:"generatedAt"`
	DetectionPoints   []DetectionPoint `json:"detectionPoints"`
	Classifications   []Classification `json:"classifications"`
	SuggestedProfiles []string         `json:"suggestedProfiles"`
	RequiredConfirm   bool             `json:"requiredConfirm"`
	TargetScoped      bool             `json:"targetScoped"`
	RuntimeOnly       bool             `json:"runtimeOnly"`
	Notes             []string         `json:"notes"`
}

type detectionRule struct {
	Protection  string
	Category    string
	Confidence  string
	Rule        string
	Any         []string
	All         []string
	Score       int
	Description string
}

var detectionRules = []detectionRule{
	// Debugger detection: high confidence when known APIs or TracerPid/proc patterns are present.
	{Protection: "debugger_detection", Rule: "android_debug_api", Category: "java_debug_api", Any: []string{"android.os.Debug", "isDebuggerConnected", "waitingForDebugger", "waitForDebugger", "Landroid/os/Debug;"}, Score: 90, Confidence: "high", Description: "References Android debugger APIs."},
	{Protection: "debugger_detection", Rule: "proc_status_tracerpid", Category: "proc_status", All: []string{"/proc/self/status", "TracerPid"}, Score: 90, Confidence: "high", Description: "Reads TracerPid from /proc/self/status."},
	{Protection: "debugger_detection", Rule: "proc_task_probe", Category: "proc_status", All: []string{"/proc/self/task", "TracerPid"}, Score: 70, Confidence: "medium", Description: "Possible thread/task proc anti-debug probe."},
	{Protection: "debugger_detection", Rule: "native_ptrace_string", Category: "native_debug_api", Any: []string{"PTRACE_TRACEME", "ptrace"}, Score: 55, Confidence: "medium", Description: "Mentions ptrace; ELF imports raise this to high confidence."},
	{Protection: "debugger_detection", Rule: "debuggable_property", Category: "system_property", Any: []string{"ro.debuggable", "ro.secure", "jdwp", "JDWP"}, Score: 45, Confidence: "medium", Description: "Checks debuggable/JDWP related properties or strings."},
	{Protection: "debugger_detection", Rule: "anti_debug_name_hint", Category: "name_hint", Any: []string{"anti_debug", "antiDebug", "debugger"}, Score: 20, Confidence: "low", Description: "Only naming/string hint; may be false positive."},

	// Frida detection: only raw 'frida' is low; maps/ports/gum/gadget combinations are stronger.
	{Protection: "frida_detection", Rule: "frida_maps_scan", Category: "proc_maps", All: []string{"/proc/self/maps", "frida"}, Score: 90, Confidence: "high", Description: "Looks for Frida strings in process maps."},
	{Protection: "frida_detection", Rule: "frida_gum_gadget", Category: "runtime_artifact", Any: []string{"gum-js-loop", "frida-gadget", "frida-server", "linjector"}, Score: 85, Confidence: "high", Description: "References well-known Frida runtime artifacts."},
	{Protection: "frida_detection", Rule: "frida_port_probe", Category: "port_probe", Any: []string{"27042", "27043"}, Score: 60, Confidence: "medium", Description: "References common Frida server ports."},
	{Protection: "frida_detection", Rule: "frida_keyword_only", Category: "keyword", Any: []string{"frida"}, Score: 25, Confidence: "low", Description: "Only Frida keyword found; may be documentation/log text."},

	// Root detection: path + action/co-occurrence is high; naked words are low.
	{Protection: "root_detection", Rule: "su_path_check", Category: "su_path", All: []string{"/system/xbin/su"}, Score: 80, Confidence: "high", Description: "References a common su binary path."},
	{Protection: "root_detection", Rule: "su_system_bin_check", Category: "su_path", All: []string{"/system/bin/su"}, Score: 80, Confidence: "high", Description: "References a common su binary path."},
	{Protection: "root_detection", Rule: "rootbeer_api", Category: "known_library", Any: []string{"RootBeer", "isRooted", "detectRoot", "isDeviceRooted", "checkRoot"}, Score: 75, Confidence: "high", Description: "References common root-check APIs or libraries."},
	{Protection: "root_detection", Rule: "build_tags_test_keys", Category: "build_tags", All: []string{"test-keys", "Build.TAGS"}, Score: 65, Confidence: "medium", Description: "Checks Android build tags for test-keys."},
	{Protection: "root_detection", Rule: "root_keyword_only", Category: "keyword", Any: []string{"magisk", "busybox", "Superuser", "rooted"}, Score: 25, Confidence: "low", Description: "Only root-related keyword found; may be false positive."},

	// Emulator detection: properties/device identifiers are stronger than a single 'emulator' word.
	{Protection: "emulator_detection", Rule: "qemu_property", Category: "system_property", Any: []string{"ro.kernel.qemu", "ro.hardware", "ro.product.model"}, All: []string{"qemu"}, Score: 80, Confidence: "high", Description: "Checks emulator/QEMU system properties."},
	{Protection: "emulator_detection", Rule: "emulator_device_ids", Category: "device_fingerprint", Any: []string{"goldfish", "ranchu", "Genymotion", "BlueStacks", "Nox"}, Score: 70, Confidence: "medium", Description: "References common emulator device identifiers."},
	{Protection: "emulator_detection", Rule: "emulator_keyword_only", Category: "keyword", Any: []string{"emulator"}, Score: 20, Confidence: "low", Description: "Only emulator keyword found; may be false positive."},

	// Traffic-capture / TLS interception detection: SSL pinning, proxy/VPN checks, user CA policy.
	{Protection: "traffic_capture_detection", Rule: "okhttp_certificate_pinner", Category: "ssl_pinning", Any: []string{"okhttp3.CertificatePinner", "Lokhttp3/CertificatePinner;"}, Score: 95, Confidence: "high", Description: "References OkHttp CertificatePinner."},
	{Protection: "traffic_capture_detection", Rule: "trustkit_pinning", Category: "ssl_pinning", Any: []string{"TrustKit", "PinningTrustManager", "pinningTrustManager"}, Score: 90, Confidence: "high", Description: "References known TLS pinning libraries/classes."},
	{Protection: "traffic_capture_detection", Rule: "network_security_pin_set", Category: "network_security_config", All: []string{"pin-set", "digest=\"SHA-256\""}, Score: 90, Confidence: "high", Description: "Network Security Config contains certificate pin-set entries."},
	{Protection: "traffic_capture_detection", Rule: "certificate_hash_pinning", Category: "ssl_pinning", All: []string{"sha256/"}, Any: []string{"pin", "certificate", "public key", "X509Certificate"}, Score: 75, Confidence: "medium", Description: "References certificate/public-key SHA-256 pinning material."},
	{Protection: "traffic_capture_detection", Rule: "conscrypt_trustmanager_hook_point", Category: "ssl_pinning", Any: []string{"TrustManagerImpl", "checkServerTrusted", "checkTrustedRecursive", "X509TrustManager"}, Score: 55, Confidence: "medium", Description: "References TrustManager/Conscrypt certificate validation paths."},
	{Protection: "traffic_capture_detection", Rule: "hostname_verifier", Category: "ssl_validation", Any: []string{"HostnameVerifier", "verifyHostname", "SSLPeerUnverifiedException"}, Score: 45, Confidence: "medium", Description: "References hostname/certificate validation code paths."},
	{Protection: "traffic_capture_detection", Rule: "proxy_detection", Category: "proxy_detection", Any: []string{"http.proxyHost", "http.proxyPort", "ProxySelector", "java.net.Proxy", "getDefaultProxy"}, Score: 55, Confidence: "medium", Description: "References system proxy detection APIs or properties."},
	{Protection: "traffic_capture_detection", Rule: "vpn_detection", Category: "vpn_detection", Any: []string{"TRANSPORT_VPN", "VpnService", "tun0", "ppp0", "getNetworkCapabilities"}, Score: 55, Confidence: "medium", Description: "References VPN/interface detection signals."},
	{Protection: "traffic_capture_detection", Rule: "mitm_tool_keywords", Category: "mitm_tool_hint", Any: []string{"mitmproxy", "charles", "fiddler", "burp"}, Score: 25, Confidence: "low", Description: "Only common MITM tool keyword found; may be documentation/log text."},
}

func LoadProfile(dir, name string) (*BypassProfile, string, error) {
	safe := SafeName(name)
	candidates := []string{filepath.Join(dir, safe), filepath.Join(dir, safe+".json")}
	for _, p := range candidates {
		b, err := os.ReadFile(p)
		if err == nil {
			var prof BypassProfile
			if err := json.Unmarshal(b, &prof); err != nil {
				return nil, p, err
			}
			if prof.Name == "" {
				prof.Name = strings.TrimSuffix(filepath.Base(p), filepath.Ext(p))
			}
			return &prof, p, nil
		}
	}
	return nil, "", fmt.Errorf("profile %q not found in %s", name, dir)
}

func ListProfiles(dir string) ([]BypassProfile, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return []BypassProfile{}, nil
		}
		return nil, err
	}
	out := []BypassProfile{}
	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".json") {
			continue
		}
		p, _, err := LoadProfile(dir, ent.Name())
		if err == nil {
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func ScanAPK(apkPath string) ([]DetectionPoint, error) {
	zr, err := zip.OpenReader(apkPath)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	points := []DetectionPoint{}
	seen := map[string]bool{}
	for _, f := range zr.File {
		lowerName := strings.ToLower(f.Name)
		interesting := strings.HasSuffix(lowerName, ".dex") || strings.HasSuffix(lowerName, ".so") || strings.Contains(lowerName, "manifest") || strings.HasSuffix(lowerName, ".xml") || strings.HasSuffix(lowerName, ".arsc")
		if !interesting {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(rc, 64*1024*1024))
		_ = rc.Close()
		if strings.HasSuffix(lowerName, ".so") {
			for _, p := range scanELFDetectionPoints(f.Name, b) {
				key := p.Protection + "\x00" + p.Source + "\x00" + p.Rule + "\x00" + p.Evidence
				if seen[key] {
					continue
				}
				seen[key] = true
				points = append(points, p)
			}
		}
		hay := bytes.ToLower(b)
		for _, rule := range detectionRules {
			if !matchDetectionRule(hay, lowerName, rule) {
				continue
			}
			keywords := hitKeywords(hay, lowerName, rule)
			evs := collectEvidence(hay, b, lowerName, keywords)
			primary := ""
			if len(keywords) > 0 {
				primary = keywords[0]
			}
			ev := ""
			if len(evs) > 0 {
				ev = evs[0]
			}
			key := rule.Protection + "\x00" + f.Name + "\x00" + rule.Rule + "\x00" + strings.Join(evs, "\x00")
			if seen[key] {
				continue
			}
			seen[key] = true
			points = append(points, DetectionPoint{
				Protection:   rule.Protection,
				Source:       f.Name,
				Keyword:      primary,
				Keywords:     keywords,
				Category:     rule.Category,
				Rule:         rule.Rule,
				Evidence:     ev,
				EvidenceList: evs,
				Score:        rule.Score,
				Confidence:   rule.Confidence,
				Reason:       rule.Description,
			})
		}
	}
	sort.Slice(points, func(i, j int) bool {
		if points[i].Protection == points[j].Protection {
			if points[i].Source == points[j].Source {
				return points[i].Score > points[j].Score
			}
			return points[i].Source < points[j].Source
		}
		return points[i].Protection < points[j].Protection
	})
	return points, nil
}

func matchDetectionRule(hay []byte, lowerName string, rule detectionRule) bool {
	for _, kw := range rule.All {
		lowerKW := strings.ToLower(kw)
		if !bytes.Contains(hay, []byte(lowerKW)) && !strings.Contains(lowerName, lowerKW) {
			return false
		}
	}
	if len(rule.Any) == 0 {
		return len(rule.All) > 0
	}
	for _, kw := range rule.Any {
		lowerKW := strings.ToLower(kw)
		if bytes.Contains(hay, []byte(lowerKW)) || strings.Contains(lowerName, lowerKW) {
			return true
		}
	}
	return false
}

func hitKeywords(hay []byte, lowerName string, rule detectionRule) []string {
	out := []string{}
	seen := map[string]bool{}
	addIfHit := func(kw string, required bool) {
		lowerKW := strings.ToLower(kw)
		if required || bytes.Contains(hay, []byte(lowerKW)) || strings.Contains(lowerName, lowerKW) {
			key := strings.ToLower(kw)
			if !seen[key] {
				seen[key] = true
				out = append(out, kw)
			}
		}
	}
	for _, kw := range rule.All {
		addIfHit(kw, true)
	}
	for _, kw := range rule.Any {
		addIfHit(kw, false)
	}
	return out
}

func Classify(points []DetectionPoint) []Classification {
	counts := map[string]int{}
	scores := map[string]int{}
	hasHigh := map[string]bool{}
	for _, p := range points {
		counts[p.Protection]++
		scores[p.Protection] += p.Score
		if p.Confidence == "high" && p.Score >= 75 {
			hasHigh[p.Protection] = true
		}
	}
	prots := []string{"root_detection", "debugger_detection", "emulator_detection", "frida_detection", "traffic_capture_detection"}
	out := []Classification{}
	for _, prot := range prots {
		n := counts[prot]
		score := scores[prot]
		level := "none"
		if score > 0 {
			level = "low"
		}
		if score >= 60 {
			level = "medium"
		}
		if score >= 120 || hasHigh[prot] {
			level = "high"
		}
		out = append(out, Classification{Protection: prot, Level: level, Count: n, Score: score, Summary: fmt.Sprintf("%s: %s (score=%d, rule hits=%d)", prot, level, score, n)})
	}
	return out
}

func GeneratePlan(packageName string, points []DetectionPoint, profiles []BypassProfile) BypassPlan {
	cls := Classify(points)
	detected := map[string]bool{}
	for _, c := range cls {
		if c.Level == "medium" || c.Level == "high" {
			detected[c.Protection] = true
		}
	}
	suggestions := []string{}
	for _, p := range profiles {
		for _, prot := range p.Protections {
			if detected[prot] {
				suggestions = append(suggestions, p.Name)
				break
			}
		}
	}
	sort.Strings(suggestions)
	return BypassPlan{
		PackageName:       packageName,
		GeneratedAt:       time.Now().UTC(),
		DetectionPoints:   points,
		Classifications:   cls,
		SuggestedProfiles: suggestions,
		RequiredConfirm:   true,
		TargetScoped:      true,
		RuntimeOnly:       true,
		Notes: []string{
			"CTF Bypass Mode is restricted to CTF, lab, self-owned, or explicitly authorized apps.",
			"Bypass execution requires ctfBypassEnabled=true, package allow-list membership, and confirm=true.",
			"Runtime profiles are loaded only into the target package process and are not global device patches.",
		},
	}
}

func GenerateFridaScript(packageName string, profiles []BypassProfile) string {
	var b strings.Builder
	b.WriteString("'use strict';\n")
	b.WriteString("// Generated by android-sec-mcp CTF Bypass Mode. Target-scoped runtime profile.\n")
	b.WriteString("const TARGET_PACKAGE = " + jsonString(packageName) + ";\n")
	b.WriteString("function log(x) { console.log('[ctf-bypass] ' + x); }\n")
	b.WriteString("function safeHookJava(className, methodName, returnType, returnValue) {\n")
	b.WriteString("  try {\n")
	b.WriteString("    const C = Java.use(className);\n")
	b.WriteString("    if (!C[methodName]) { log('missing method ' + className + '.' + methodName); return; }\n")
	b.WriteString("    C[methodName].overloads.forEach(function(ov) {\n")
	b.WriteString("      ov.implementation = function() {\n")
	b.WriteString("        log('hit ' + className + '.' + methodName + ' argc=' + arguments.length);\n")
	b.WriteString("        if (returnType === 'boolean') return !!returnValue;\n")
	b.WriteString("        if (returnType === 'int') return returnValue | 0;\n")
	b.WriteString("        if (returnType === 'string') return String(returnValue || '');\n")
	b.WriteString("        if (returnType === 'void') return;\n")
	b.WriteString("        return ov.apply(this, arguments);\n")
	b.WriteString("      };\n")
	b.WriteString("    });\n")
	b.WriteString("    log('hooked ' + className + '.' + methodName);\n")
	b.WriteString("  } catch (e) { log('hook failed ' + className + '.' + methodName + ': ' + e); }\n")
	b.WriteString("}\n")
	b.WriteString("if (Java.available) { Java.perform(function() {\n")
	b.WriteString("  let appPkg = '<unknown>'; try { appPkg = Java.use('android.app.ActivityThread').currentPackageName(); } catch (e) {}\n")
	b.WriteString("  if (appPkg !== TARGET_PACKAGE) { log('refuse non-target package ' + appPkg); return; }\n")
	b.WriteString("  log('loading profiles for ' + appPkg);\n")
	for _, p := range profiles {
		b.WriteString("  // Profile: " + escapeLine(p.Name) + " - " + escapeLine(p.Description) + "\n")
		for _, a := range p.Actions {
			switch a.Type {
			case "java_return":
				b.WriteString(fmt.Sprintf("  safeHookJava(%s, %s, %s, %s);\n", jsonString(a.ClassName), jsonString(a.MethodName), jsonString(a.ReturnType), jsonValue(a.ReturnValue)))
			case "frida_script":
				b.WriteString("  // Custom script action from profile " + escapeLine(p.Name) + "\n")
				b.WriteString(a.Script)
				if !strings.HasSuffix(a.Script, "\n") {
					b.WriteString("\n")
				}
			default:
				b.WriteString("  log('unsupported action type: " + escapeLine(a.Type) + "');\n")
			}
		}
	}
	b.WriteString("}); } else { log('Java runtime not available'); }\n")
	return b.String()
}

func GenerateDebuggerBypassScript(packageName string, points []DetectionPoint) string {
	var b strings.Builder
	b.WriteString("'use strict';\n")
	b.WriteString("// Generated by android-sec-mcp. Target-scoped anti-debug bypass for CTF/lab/authorized testing.\n")
	b.WriteString("const TARGET_PACKAGE = " + jsonString(packageName) + ";\n")
	b.WriteString("function log(x) { console.log('[anti-debug] ' + x); }\n")
	b.WriteString("const detectionPoints = " + jsonValue(points) + ";\n")
	b.WriteString("log('detection points: ' + detectionPoints.length);\n")
	b.WriteString(`
function hookJavaAntiDebug() {
  Java.perform(function () {
    let appPkg = '<unknown>';
    try { appPkg = Java.use('android.app.ActivityThread').currentPackageName(); } catch (e) {}
    if (appPkg !== TARGET_PACKAGE) { log('refuse non-target package ' + appPkg); return; }

    function hookReturn(className, methodName, value) {
      try {
        const C = Java.use(className);
        if (!C[methodName]) { log('missing ' + className + '.' + methodName); return; }
        C[methodName].overloads.forEach(function (ov) {
          ov.implementation = function () {
            log(className + '.' + methodName + ' => ' + value);
            return value;
          };
        });
        log('hooked ' + className + '.' + methodName);
      } catch (e) { log('hookReturn failed ' + className + '.' + methodName + ': ' + e); }
    }

    function hookNoop(className, methodName) {
      try {
        const C = Java.use(className);
        if (!C[methodName]) { log('missing ' + className + '.' + methodName); return; }
        C[methodName].overloads.forEach(function (ov) {
          ov.implementation = function () {
            log(className + '.' + methodName + ' noop');
            return;
          };
        });
        log('hooked noop ' + className + '.' + methodName);
      } catch (e) { log('hookNoop failed ' + className + '.' + methodName + ': ' + e); }
    }

    hookReturn('android.os.Debug', 'isDebuggerConnected', false);
    hookReturn('android.os.Debug', 'waitingForDebugger', false);
    hookNoop('android.os.Debug', 'waitForDebugger');

    try {
      const BR = Java.use('java.io.BufferedReader');
      BR.readLine.overloads.forEach(function (ov) {
        ov.implementation = function () {
          const line = ov.apply(this, arguments);
          if (line !== null) {
            const s = String(line);
            if (s.indexOf('TracerPid:') >= 0) {
              log('hide ' + s);
              return s.replace(/[0-9]+/g, '0');
            }
          }
          return line;
        };
      });
      log('hooked BufferedReader.readLine TracerPid');
    } catch (e) { log('BufferedReader hook failed: ' + e); }
  });
}

function hookNativeAntiDebug() {
  try {
    const ptrace = Module.findExportByName(null, 'ptrace') || Module.findExportByName('libc.so', 'ptrace');
    if (ptrace) {
      Interceptor.replace(ptrace, new NativeCallback(function (request, pid, addr, data) {
        log('ptrace(' + request + ', ' + pid + ') => 0');
        return 0;
      }, 'int', ['int', 'int', 'pointer', 'pointer']));
      log('replaced libc.ptrace');
    } else {
      log('ptrace export not found');
    }
  } catch (e) { log('ptrace hook failed: ' + e); }

  try {
    const syscall = Module.findExportByName(null, 'syscall') || Module.findExportByName('libc.so', 'syscall');
    const nrMap = { arm64: 117, x64: 101, ia32: 26, arm: 26 };
    const nrPtrace = nrMap[Process.arch];
    if (syscall && nrPtrace !== undefined) {
      Interceptor.attach(syscall, {
        onEnter: function (args) {
          this.isPtrace = args[0].toInt32() === nrPtrace;
          if (this.isPtrace) log('syscall ptrace nr=' + nrPtrace);
        },
        onLeave: function (retval) {
          if (this.isPtrace) retval.replace(0);
        }
      });
      log('hooked syscall ptrace for arch=' + Process.arch + ' nr=' + nrPtrace);
    }
  } catch (e) { log('syscall hook failed: ' + e); }
}

setImmediate(function () {
  hookNativeAntiDebug();
  if (Java.available) hookJavaAntiDebug();
  else log('Java runtime not available');
});
`)
	return b.String()
}

func scanELFDetectionPoints(source string, b []byte) []DetectionPoint {
	ef, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil
	}
	defer ef.Close()

	syms, err := ef.DynamicSymbols()
	if err != nil {
		return nil
	}
	imports := map[string]bool{}
	for _, s := range syms {
		if s.Name == "" {
			continue
		}
		// Undefined dynamic symbols are imported from other shared objects.
		if s.Section == elf.SHN_UNDEF {
			imports[s.Name] = true
		}
	}
	lower := bytes.ToLower(b)
	out := []DetectionPoint{}
	add := func(protection, rule, category string, keywords []string, score int, confidence, reason string) {
		evs := collectEvidence(lower, b, strings.ToLower(source), keywords)
		primary := ""
		if len(keywords) > 0 {
			primary = keywords[0]
		}
		ev := ""
		if len(evs) > 0 {
			ev = evs[0]
		}
		out = append(out, DetectionPoint{
			Protection:   protection,
			Source:       source,
			Keyword:      primary,
			Keywords:     keywords,
			Category:     category,
			Rule:         rule,
			Evidence:     ev,
			EvidenceList: evs,
			Score:        score,
			Confidence:   confidence,
			Reason:       reason,
		})
	}
	hasImport := func(names ...string) bool {
		for _, n := range names {
			if imports[n] {
				return true
			}
		}
		return false
	}
	has := func(kw string) bool { return bytes.Contains(lower, bytes.ToLower([]byte(kw))) }

	if hasImport("ptrace") {
		add("debugger_detection", "elf_import_ptrace", "native_import", []string{"ptrace"}, 95, "high", "Native ELF imports ptrace, a strong anti-debug indicator.")
	}
	if hasImport("syscall") && (has("ptrace") || has("PTRACE_TRACEME")) {
		add("debugger_detection", "elf_syscall_ptrace", "native_import", []string{"syscall", "ptrace", "PTRACE_TRACEME"}, 85, "high", "Native ELF imports syscall and references ptrace.")
	}
	if hasImport("open", "openat", "fopen", "read") && has("/proc/self/status") && has("TracerPid") {
		add("debugger_detection", "elf_read_tracerpid", "native_proc_status", []string{"/proc/self/status", "TracerPid", "open/fopen/read"}, 95, "high", "Native ELF appears to read TracerPid from /proc/self/status.")
	}
	if hasImport("open", "openat", "fopen", "read") && has("/proc/self/maps") && has("frida") {
		add("frida_detection", "elf_scan_proc_maps_frida", "native_proc_maps", []string{"/proc/self/maps", "frida", "open/fopen/read"}, 95, "high", "Native ELF appears to scan process maps for Frida artifacts.")
	}
	if hasImport("connect", "sendto", "recvfrom") && (has("27042") || has("27043")) {
		add("frida_detection", "elf_probe_frida_port", "native_socket_probe", []string{"connect/sendto/recvfrom", "27042", "27043"}, 75, "medium", "Native ELF references common Frida server ports and socket APIs.")
	}
	if hasImport("access", "stat", "lstat", "open", "openat", "fopen") && (has("/system/xbin/su") || has("/system/bin/su") || has("/sbin/su")) {
		add("root_detection", "elf_check_su_path", "native_file_check", []string{"access/stat/open/fopen", "/system/xbin/su", "/system/bin/su", "/sbin/su"}, 90, "high", "Native ELF checks common su binary paths.")
	}
	if hasImport("__system_property_get") && (has("ro.kernel.qemu") || has("goldfish") || has("ranchu") || has("qemu")) {
		add("emulator_detection", "elf_emulator_property_check", "native_system_property", []string{"__system_property_get", "ro.kernel.qemu", "goldfish", "ranchu", "qemu"}, 85, "high", "Native ELF reads Android system properties associated with emulators.")
	}
	if hasImport("SSL_get_peer_certificate", "SSL_get0_peer_certificate", "SSL_get1_peer_certificate") && hasImport("X509_verify_cert", "X509_digest", "X509_get_pubkey", "i2d_X509", "EVP_Digest", "EVP_sha256") {
		add("traffic_capture_detection", "elf_native_tls_peer_cert_pinning", "native_ssl_pinning", []string{"SSL_get_peer_certificate", "X509_verify_cert", "X509_digest", "X509_get_pubkey", "EVP_sha256"}, 95, "high", "Native ELF imports peer-certificate and X509/hash APIs commonly used for SSL pinning.")
	}
	if hasImport("X509_digest", "X509_get_pubkey", "i2d_X509", "EVP_Digest", "EVP_sha256", "EVP_sha1") && (has("sha256") || has("sha256/") || has("pin") || has("certificate pin")) {
		add("traffic_capture_detection", "elf_native_cert_hash_pinning", "native_ssl_pinning", []string{"X509_digest", "X509_get_pubkey", "EVP_sha256", "sha256", "pin"}, 90, "high", "Native ELF combines certificate hash APIs with pinning strings.")
	}
	if hasImport("SSL_set_verify", "SSL_CTX_set_verify") && (has("pin") || has("verify") || has("certificate")) {
		add("traffic_capture_detection", "elf_native_ssl_verify_callback", "native_ssl_validation", []string{"SSL_set_verify", "SSL_CTX_set_verify", "pin", "certificate"}, 70, "medium", "Native ELF configures SSL verification callbacks and contains pinning/verification strings.")
	}
	if hasImport("getenv", "getprop", "__system_property_get") && (has("http_proxy") || has("https_proxy") || has("http.proxyhost") || has("http.proxyport")) {
		add("traffic_capture_detection", "elf_native_proxy_detection", "native_proxy_detection", []string{"getenv/__system_property_get", "http_proxy", "https_proxy", "http.proxyHost", "http.proxyPort"}, 65, "medium", "Native ELF appears to check proxy-related environment/properties.")
	}
	if hasImport("getifaddrs", "ioctl") && (has("tun0") || has("ppp0") || has("vpn")) {
		add("traffic_capture_detection", "elf_native_vpn_interface_detection", "native_vpn_detection", []string{"getifaddrs/ioctl", "tun0", "ppp0", "vpn"}, 65, "medium", "Native ELF appears to check VPN/tunnel interfaces.")
	}
	return out
}

func collectEvidence(hay, b []byte, lowerName string, keywords []string) []string {
	out := []string{}
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, kw := range keywords {
		if ev := snippet(hay, b, kw); ev != "" {
			add(ev)
		} else if strings.Contains(lowerName, strings.ToLower(kw)) {
			add("filename contains " + kw)
		}
		if len(out) >= 8 {
			break
		}
	}
	return out
}

func snippet(hay, b []byte, kw string) string {
	lowerKW := bytes.ToLower([]byte(kw))
	idx := bytes.Index(hay, lowerKW)
	if idx < 0 {
		return ""
	}
	start := idx - 48
	if start < 0 {
		start = 0
	}
	end := idx + len(kw) + 48
	if end > len(hay) {
		end = len(hay)
	}
	// Clamp into the original b: bytes.ToLower on binary data may expand the
	// slice (invalid UTF-8 sequences become 3-byte replacement chars), so idx
	// from the lowered copy can exceed len(b).
	if start >= len(b) {
		return ""
	}
	if end > len(b) {
		end = len(b)
	}
	s := string(b[start:end])
	s = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return '.'
		}
		return r
	}, s)
	return s
}

func jsonString(s string) string { b, _ := json.Marshal(s); return string(b) }
func jsonValue(v any) string {
	b, _ := json.Marshal(v)
	if len(b) == 0 {
		return "null"
	}
	return string(b)
}
func escapeLine(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\r", " ")
}
