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

// tokenBounded accepts matches that end at a token boundary and satisfy
// extra (if set). Pair it with leftCheck(tokenLeft).
func tokenBounded(extra func(m string) bool) acceptFunc {
	return func(text string, s, e int) (int, bool) {
		if !tokenRight(text, e) {
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
		`(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}`, tokenBounded(nil), leftCheck(tokenLeft))
}

// NewGitHubToken detects classic (ghp_, gho_, ghu_, ghs_, ghr_) and
// fine-grained (github_pat_) GitHub tokens.
func NewGitHubToken() (Detector, error) {
	return newPattern(KindGitHubToken, CategorySecret, 95, 1,
		`gh[pousr]_[A-Za-z0-9]{36,251}|github_pat_[A-Za-z0-9_]{22,240}`, tokenBounded(nil), leftCheck(tokenLeft))
}

// NewSlackToken detects Slack bot/user/app tokens.
func NewSlackToken() (Detector, error) {
	return newPattern(KindSlackToken, CategorySecret, 95, 1,
		`xox[abposr]-[A-Za-z0-9\-]{10,250}`, tokenBounded(hasDigit), leftCheck(tokenLeft))
}

// NewStripeKey detects Stripe secret and restricted keys.
func NewStripeKey() (Detector, error) {
	return newPattern(KindStripeKey, CategorySecret, 95, 1,
		`[rs]k_(?:live|test)_[A-Za-z0-9]{16,247}`, tokenBounded(nil), leftCheck(tokenLeft))
}

// NewGoogleAPIKey detects Google Cloud API keys.
func NewGoogleAPIKey() (Detector, error) {
	return newPattern(KindGoogleAPIKey, CategorySecret, 95, 1,
		`AIza[0-9A-Za-z_\-]{35}`, tokenBounded(nil), leftCheck(tokenLeft))
}

// NewLLMAPIKey detects OpenAI-style (sk-, sk-proj-) and Anthropic-style
// (sk-ant-...) API keys. The random tail must look random.
func NewLLMAPIKey() (Detector, error) {
	return newPattern(KindLLMAPIKey, CategorySecret, 95, 1,
		`sk-(?:proj-|ant-[a-z]{3,5}[0-9]{2}-)?[A-Za-z0-9_\-]{20,180}`,
		tokenBounded(func(m string) bool {
			body := llmKeyPrefix.ReplaceAllString(m, "")
			return hasDigit(body) && ShannonEntropy(body) >= 3.0
		}), leftCheck(tokenLeft))
}

var llmKeyPrefix = regexp.MustCompile(`^sk-(?:proj-|ant-[a-z]{3,5}[0-9]{2}-)?`)

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
		}), leftCheck(tokenLeft))
}

// NewPrivateKey detects PEM private key headers.
func NewPrivateKey() (Detector, error) {
	return newPattern(KindPrivateKey, CategorySecret, 100, 0,
		`-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----`, nil)
}

// credentialKeys are key names whose assigned value is treated as a secret.
var credentialKeys = []string{
	"password", "passwd", "pwd", "passphrase", "secret", "apikey", "api_key", "api-key",
	"access_token", "access-token", "accesstoken", "auth_token", "auth-token", "authtoken",
	"client_secret", "client-secret", "clientsecret",
}

// credValueChars are the bytes a credential value may contain.
const credValueChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*_+=/~-"

var (
	credValue    = AlphabetOf(credValueChars)
	credAlphabet = AlphabetOf(credValueChars, ".?")
)

// credentialDetector finds values assigned to credential-named keys, such
// as `password: hunter2!` or `API_KEY="..."`. The key and operator are left
// context; only the value is reported. It scans for ':' and '=' rather than
// running a regex at every word, which keeps it cheap on prose.
type credentialDetector struct{}

// NewCredentialAssignment returns the credential-assignment detector.
func NewCredentialAssignment() (Detector, error) { return credentialDetector{}, nil }

const (
	credMinLen = 6
	credMaxLen = 64
	// credMaxGap bounds operator-to-value distance: `: "` plus spacing.
	credMaxGap = 5
)

func (credentialDetector) Kind() Kind             { return KindCredentialPair }
func (credentialDetector) Category() Category     { return CategorySecret }
func (credentialDetector) Priority() int          { return 85 }
func (credentialDetector) MaxLen() int            { return credMaxLen }
func (credentialDetector) LeftContext() int       { return keywordWindow }
func (credentialDetector) InAlphabet(b byte) bool { return credAlphabet.Contains(b) }

func (d credentialDetector) FindFrom(text string, from int) (int, int, bool) {
	for p := max(0, from-credMaxGap); p < len(text); p++ {
		if c := text[p]; c != ':' && c != '=' {
			continue
		}
		v, ok := valueStart(text, p)
		if !ok || v < from {
			continue
		}
		if e, ok := d.accept(text, v); ok {
			return v, e, true
		}
	}
	return 0, 0, false
}

// valueStart checks that the operator at p follows a credential key and
// returns where the value begins.
func valueStart(text string, p int) (int, bool) {
	k := p
	for k > 0 && p-k < 3 && (text[k-1] == ' ' || text[k-1] == '\t') {
		k--
	}
	if k > 0 && (text[k-1] == '"' || text[k-1] == '\'') {
		k--
	}
	key := strings.ToLower(text[max(0, k-16):k])
	found := false
	for _, w := range credentialKeys {
		if strings.HasSuffix(key, w) {
			found = true
			break
		}
	}
	if !found {
		return 0, false
	}
	v := p + 1
	for v < len(text) && v-p <= 3 && (text[v] == ' ' || text[v] == '\t') {
		v++
	}
	if v < len(text) && (text[v] == '"' || text[v] == '\'') {
		v++
	}
	return v, v-p <= credMaxGap
}

func (credentialDetector) accept(text string, v int) (int, bool) {
	e := v
	for e < len(text) && credAlphabet.Contains(text[e]) {
		e++
		if e-v > credMaxLen {
			return 0, false // longer values are not truncated-and-reported
		}
	}
	for e > v && !credValue.Contains(text[e-1]) {
		e-- // trailing sentence punctuation
	}
	if e-v < credMinLen {
		return 0, false
	}
	val := text[v:e]
	if val[0] == '$' || strings.Contains(strings.ToUpper(val), "REDACTED") || allSame(val) {
		return 0, false
	}
	return e, charClasses(val) >= 2
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
