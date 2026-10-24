package detect

import (
	"encoding/base64"
	"encoding/json"
	"regexp"
	"strings"
)

// tokenRight: the byte at e does not continue a token.
func tokenRight(text string, e int) bool {
	c := byteAt(text, e)
	return !isAlnum(c) && c != '_' && c != '-'
}

// tokenLeft: the byte before s does not continue a token.
func tokenLeft(text string, s int) bool {
	c := byteAt(text, s-1)
	return !isAlnum(c) && c != '_' && c != '-'
}

func tokenBounded(extra func(m string) bool) acceptFunc {
	return func(text string, s, e int) (int, bool) {
		if !tokenLeft(text, s) || !tokenRight(text, e) {
			return 0, false
		}
		if extra != nil && !extra(text[s:e]) {
			return 0, false
		}
		return e, true
	}
}

// NewAWSAccessKey detects AWS access key IDs (AKIA/ASIA/ABIA/ACCA prefixes).
func NewAWSAccessKey() (Detector, error) {
	return newPattern(KindAWSAccessKey, CategorySecret, 95, 1,
		`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, tokenBounded(nil))
}

// NewGitHubToken detects classic (ghp_, gho_, ghu_, ghs_, ghr_) and
// fine-grained (github_pat_) GitHub tokens.
func NewGitHubToken() (Detector, error) {
	return newPattern(KindGitHubToken, CategorySecret, 95, 1,
		`gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,240}`, tokenBounded(nil))
}

// NewSlackToken detects Slack bot/user/app tokens.
func NewSlackToken() (Detector, error) {
	return newPattern(KindSlackToken, CategorySecret, 95, 1,
		`xox[abposr]-[A-Za-z0-9\-]{10,250}`, tokenBounded(hasDigit))
}

// NewStripeKey detects Stripe secret and restricted keys.
func NewStripeKey() (Detector, error) {
	return newPattern(KindStripeKey, CategorySecret, 95, 1,
		`[rs]k_(?:live|test)_[A-Za-z0-9]{16,247}`, tokenBounded(nil))
}

// NewGoogleAPIKey detects Google Cloud API keys.
func NewGoogleAPIKey() (Detector, error) {
	return newPattern(KindGoogleAPIKey, CategorySecret, 95, 1,
		`AIza[0-9A-Za-z_\-]{35}`, tokenBounded(nil))
}

// NewLLMAPIKey detects OpenAI-style (sk-, sk-proj-) and Anthropic-style
// (sk-ant-...) API keys. The random tail must look random.
func NewLLMAPIKey() (Detector, error) {
	return newPattern(KindLLMAPIKey, CategorySecret, 95, 1,
		`sk-(?:proj-|ant-[a-z]{3,5}[0-9]{2}-)?[A-Za-z0-9_\-]{20,180}`,
		tokenBounded(func(m string) bool {
			tail := m[strings.LastIndexByte(m, '-')+1:]
			return hasDigit(m) && ShannonEntropy(tail) >= 3.0
		}))
}

// NewJWT detects JSON Web Tokens whose header decodes to a JSON object with
// an "alg" or "typ" member.
func NewJWT() (Detector, error) {
	return newPattern(KindJWT, CategorySecret, 90, 1,
		`eyJ[A-Za-z0-9_\-]{5,1000}\.eyJ[A-Za-z0-9_\-]{5,1000}\.[A-Za-z0-9_\-]{0,1000}`,
		tokenBounded(func(m string) bool {
			hdr, err := base64.RawURLEncoding.DecodeString(m[:strings.IndexByte(m, '.')])
			if err != nil {
				return false
			}
			var obj map[string]any
			if json.Unmarshal(hdr, &obj) != nil {
				return false
			}
			_, alg := obj["alg"]
			_, typ := obj["typ"]
			return alg || typ
		}))
}

// NewPrivateKey detects PEM private key headers.
func NewPrivateKey() (Detector, error) {
	return newPattern(KindPrivateKey, CategorySecret, 100, 0,
		`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`, nil)
}

// credentialContext matches a credential-ish key followed by an assignment
// operator at the very end of the left context window.
var credentialContext = regexp.MustCompile(
	`(?i)(?:password|passwd|pwd|passphrase|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token|client[_\-]?secret)["']?[ \t]{0,3}[:=][ \t]{0,3}["']?$`)

// NewCredentialAssignment detects values assigned to credential-named keys,
// e.g. `password: hunter2!` or `API_KEY="..."`. The key itself is left
// context; only the value is reported.
func NewCredentialAssignment() (Detector, error) {
	const expr = `[A-Za-z0-9!@#$%^&*_+=/.~?\-]{6,64}`
	return newPattern(KindCredentialPair, CategorySecret, 85, keywordWindow, expr, func(text string, s, e int) (int, bool) {
		// Trim sentence punctuation the value class also admits.
		for e > s && strings.IndexByte(".?", text[e-1]) >= 0 {
			e--
		}
		if e-s < 6 {
			return 0, false
		}
		v := text[s:e]
		if !credentialContext.MatchString(text[max(0, s-keywordWindow):s]) {
			return 0, false
		}
		if v[0] == '$' || strings.Contains(strings.ToUpper(v), "REDACTED") || allSame(v) {
			return 0, false
		}
		return e, charClasses(v) >= 2
	})
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}

func allSame(s string) bool {
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// charClasses counts lower, upper, digit and symbol classes present in s.
func charClasses(s string) int {
	var lower, upper, digit, sym bool
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isLower(c):
			lower = true
		case isUpper(c):
			upper = true
		case isDigit(c):
			digit = true
		default:
			sym = true
		}
	}
	n := 0
	for _, b := range []bool{lower, upper, digit, sym} {
		if b {
			n++
		}
	}
	return n
}
