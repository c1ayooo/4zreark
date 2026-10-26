package githubleak

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
)

func (d *Detector) fingerprint(kind, raw string) string {
	mac := hmac.New(sha256.New, d.hmacKey)
	_, _ = mac.Write([]byte(kind))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(raw))
	return hex.EncodeToString(mac.Sum(nil))
}

func lineNumberFromURL(rawURL string) int {
	u, err := url.Parse(rawURL)
	if err != nil || len(u.Fragment) < 2 || u.Fragment[0] != 'L' {
		return 0
	}
	line, err := strconv.Atoi(u.Fragment[1:])
	if err != nil || line < 1 || line > 100000000 {
		return 0
	}
	return line
}

// maskOtherSecrets is used only for defensive sanitization of internal error
// text. Candidate excerpts never call it; they are fixed markers above.
func maskOtherSecrets(value string) string {
	for _, pattern := range strongSecretPatterns {
		value = pattern.re.ReplaceAllString(value, "<redacted:"+pattern.name+">")
	}
	assignments := credentialAssignmentsForMasking(value)
	for i := len(assignments) - 1; i >= 0; i-- {
		assignment := assignments[i]
		spec, ok := classifyCredentialKey(assignment.key)
		if assignment.bearer {
			spec, ok = bearerTokenSpec, true
		} else if isClientIdentifierKey(assignment.key) {
			spec, ok = assignmentSpec{kind: "oauth_client_id"}, true
		}
		if ok {
			value = value[:assignment.valueStart] + "<redacted:" + spec.kind + ">" + value[assignment.valueEnd:]
		}
	}
	return value
}
