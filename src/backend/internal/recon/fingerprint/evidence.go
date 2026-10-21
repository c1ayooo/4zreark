package fingerprint

import (
	"sort"
	"strings"
)

// QueryMatches reports whether query looks like one of the recognized
// technologies. It accepts either direction of containment so product aliases
// such as "泛微" vs "泛微 e-cology" still match.
func QueryMatches(technologies []string, query string) bool {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return false
	}
	for _, raw := range technologies {
		tech := strings.ToLower(strings.TrimSpace(raw))
		if tech == "" {
			continue
		}
		if strings.Contains(tech, q) || strings.Contains(q, tech) {
			return true
		}
	}
	return false
}

// UniqueTechnologies returns a sorted, de-duplicated copy.
func UniqueTechnologies(technologies []string) []string {
	seen := make(map[string]bool, len(technologies))
	out := make([]string, 0, len(technologies))
	for _, raw := range technologies {
		tech := strings.TrimSpace(raw)
		if tech == "" || seen[tech] {
			continue
		}
		seen[tech] = true
		out = append(out, tech)
	}
	sort.Strings(out)
	return out
}
