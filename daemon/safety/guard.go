package safety

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

var packageRe = regexp.MustCompile(`^[A-Za-z0-9_]+(\.[A-Za-z0-9_]+)+$`)

func RequireConfirm(confirm bool, action string) error {
	if !confirm {
		return fmt.Errorf("%s requires confirm=true", action)
	}
	return nil
}

func ValidatePackageName(pkg string) error {
	if !packageRe.MatchString(pkg) {
		return fmt.Errorf("invalid packageName %q", pkg)
	}
	return nil
}

func EnsureAllowedPackage(pkg string, allowed []string) error {
	if err := ValidatePackageName(pkg); err != nil {
		return err
	}
	for _, a := range allowed {
		a = strings.TrimSpace(a)
		if a == pkg || a == "*" {
			return nil
		}
	}
	return fmt.Errorf("package %s is not in allowedBypassPackages", pkg)
}

func SafeName(name string) string {
	name = strings.TrimSpace(name)
	name = filepath.Base(name)
	repl := regexp.MustCompile(`[^A-Za-z0-9_.-]+`)
	name = repl.ReplaceAllString(name, "_")
	if name == "" || name == "." || name == ".." {
		return "case"
	}
	return name
}
