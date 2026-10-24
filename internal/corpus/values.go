// Package corpus generates the labeled synthetic data used to evaluate the
// detectors and the injection scorer, and the randomized texts used by the
// streaming property tests. Everything is deterministic for a given seed.
package corpus

import (
	"encoding/base64"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"

	"github.com/archit2501/guardrail-gw/internal/detect"
)

// Gen produces random values. Vocab selects the name/domain lists so the
// dev and held-out splits do not share surface strings.
type Gen struct {
	R     *rand.Rand
	Vocab Vocab
}

// Vocab is a split-specific word list for names and domains.
type Vocab struct {
	First, Last, Domains, TLDs []string
}

var devVocab = Vocab{
	First:   []string{"alice", "bob", "carol", "dmitri", "elena", "farah", "gustavo", "hiro", "ines", "jamal"},
	Last:    []string{"nguyen", "smith", "okafor", "garcia", "kowalski", "chen", "haddad", "silva", "ivanova", "patel"},
	Domains: []string{"example", "acme-corp", "mailhost", "northwind", "contoso"},
	TLDs:    []string{"com", "org", "io", "co.uk", "de"},
}

var heldoutVocab = Vocab{
	First:   []string{"kofi", "lucia", "mateo", "nadia", "oskar", "priya", "quentin", "rosa", "sven", "tamar"},
	Last:    []string{"mensah", "rossi", "fernandez", "lindqvist", "kaur", "dubois", "tanaka", "novak", "obi", "levi"},
	Domains: []string{"fabrikam", "globex", "initech", "umbrella-labs", "wayne-ent"},
	TLDs:    []string{"net", "dev", "com.au", "fr", "in"},
}

// NewGen returns a generator for split ("dev" or "heldout") with seed.
func NewGen(split string, seed uint64) *Gen {
	v := devVocab
	if split == "heldout" {
		v = heldoutVocab
	}
	return &Gen{R: rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)), Vocab: v}
}

func (g *Gen) pick(xs []string) string { return xs[g.R.IntN(len(xs))] }

func (g *Gen) digits(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte('0' + g.R.IntN(10))
	}
	return string(b)
}

func (g *Gen) charsFrom(alpha string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alpha[g.R.IntN(len(alpha))]
	}
	return string(b)
}

const (
	upperDigits = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	alnum       = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b64chars    = alnum + "+/"
	b64url      = alnum + "-_"
)

// Email returns a plausible address.
func (g *Gen) Email() string {
	f, l := g.pick(g.Vocab.First), g.pick(g.Vocab.Last)
	local := []string{f + "." + l, f + l[:1], f + "_" + l, f + "+" + strconv.Itoa(g.R.IntN(99)), l + strconv.Itoa(g.R.IntN(1000))}[g.R.IntN(5)]
	return local + "@" + g.pick(g.Vocab.Domains) + "." + g.pick(g.Vocab.TLDs)
}

func (g *Gen) nanpPart() (string, string, string) {
	area := strconv.Itoa(2+g.R.IntN(8)) + g.digits(2)
	exch := strconv.Itoa(2+g.R.IntN(8)) + g.digits(2)
	return area, exch, g.digits(4)
}

// Phone returns a phone number in one of several international formats.
func (g *Gen) Phone() string {
	a, e, n := g.nanpPart()
	switch g.R.IntN(8) {
	case 0:
		return "+1 " + a + "-" + e + "-" + n
	case 1:
		return "(" + a + ") " + e + "-" + n
	case 2:
		return a + "." + e + "." + n
	case 3:
		return a + "-" + e + "-" + n
	case 4:
		return "+44 20 " + g.digits(4) + " " + g.digits(4)
	case 5:
		return "+91 9" + g.digits(4) + " " + g.digits(5)
	case 6:
		return "+49 151 " + g.digits(8)
	default:
		return "0" + strconv.Itoa(1+g.R.IntN(9)) + g.digits(1) + " " + g.digits(4) + " " + g.digits(4)
	}
}

func luhnComplete(prefix string, length int) string {
	body := prefix
	for len(body) < length-1 {
		body += "0"
	}
	for c := byte('0'); c <= '9'; c++ {
		if detect.Luhn(body + string(c)) {
			return body + string(c)
		}
	}
	return body + "0"
}

// CardDigits returns a Luhn-valid card number for a random major brand.
func (g *Gen) CardDigits() string {
	type brand struct {
		prefix string
		length int
	}
	brands := []brand{
		{"4" + g.digits(5), 16}, {"5" + strconv.Itoa(1+g.R.IntN(5)) + g.digits(4), 16},
		{"3" + []string{"4", "7"}[g.R.IntN(2)] + g.digits(4), 15}, {"6011" + g.digits(2), 16},
		{"35" + strconv.Itoa(28+g.R.IntN(62)) + g.digits(2), 16}, {"62" + g.digits(4), 16},
	}
	b := brands[g.R.IntN(len(brands))]
	return luhnComplete(b.prefix+g.digits(b.length-len(b.prefix)-1), b.length)
}

// Card returns a formatted Luhn-valid card number.
func (g *Gen) Card() string { return g.formatCard(g.CardDigits()) }

func (g *Gen) formatCard(d string) string {
	sep := []string{" ", "-", ""}[g.R.IntN(3)]
	if len(d) == 15 {
		return d[:4] + sep + d[4:10] + sep + d[10:]
	}
	var parts []string
	for i := 0; i < len(d); i += 4 {
		parts = append(parts, d[i:min(i+4, len(d))])
	}
	return strings.Join(parts, sep)
}

// BadCard returns a 16-digit number that fails Luhn (a hard negative).
func (g *Gen) BadCard() string {
	d := g.CardDigits()
	last := d[len(d)-1]
	d = d[:len(d)-1] + string('0'+(last-'0'+1+byte(g.R.IntN(8)))%10)
	return g.formatCard(d)
}

var ibanCountries = []string{"DE", "GB", "FR", "ES", "NL", "IT", "CH", "BE", "AT", "PL", "SE", "IE"}

// IBAN returns a valid IBAN, compact or grouped in fours.
func (g *Gen) IBAN() string { return g.iban(true) }

// BadIBAN returns an IBAN-shaped string with a wrong check (hard negative).
func (g *Gen) BadIBAN() string { return g.iban(false) }

func (g *Gen) iban(valid bool) string {
	cc := g.pick(ibanCountries)
	n, _ := detect.IBANLength(cc)
	bban := g.digits(n - 4)
	if cc == "GB" || cc == "NL" || cc == "IE" {
		bban = g.charsFrom("ABCDEFGHIJKLMNOPQRSTUVWXYZ", 4) + g.digits(n-8)
	}
	check := 98 - mod97(bban+cc+"00")
	if !valid {
		check = (check + 1 + g.R.IntN(90)) % 97
		if check < 2 {
			check += 2
		}
	}
	s := fmt.Sprintf("%s%02d%s", cc, check, bban)
	if g.R.IntN(2) == 0 {
		return s
	}
	var parts []string
	for i := 0; i < len(s); i += 4 {
		parts = append(parts, s[i:min(i+4, len(s))])
	}
	return strings.Join(parts, " ")
}

func mod97(s string) int {
	r := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			r = (r*100 + int(c-'A') + 10) % 97
		} else {
			r = (r*10 + int(c-'0')) % 97
		}
	}
	return r
}

// SSN returns a structurally valid dashed US SSN.
func (g *Gen) SSN() string {
	area := 1 + g.R.IntN(898)
	if area == 666 {
		area = 667
	}
	return fmt.Sprintf("%03d-%02d-%04d", area, 1+g.R.IntN(99), 1+g.R.IntN(9999))
}

// BadSSN returns an SSN-shaped string violating SSA rules (hard negative).
func (g *Gen) BadSSN() string {
	switch g.R.IntN(3) {
	case 0:
		return fmt.Sprintf("000-%02d-%04d", 1+g.R.IntN(99), 1+g.R.IntN(9999))
	case 1:
		return fmt.Sprintf("666-%02d-%04d", 1+g.R.IntN(99), 1+g.R.IntN(9999))
	default:
		return fmt.Sprintf("9%02d-%02d-%04d", g.R.IntN(100), 1+g.R.IntN(99), 1+g.R.IntN(9999))
	}
}

// Aadhaar returns a Verhoeff-valid Aadhaar number grouped by spaces.
func (g *Gen) Aadhaar() string { return g.aadhaar(true) }

// BadAadhaar returns a grouped 12-digit number with a wrong check digit.
func (g *Gen) BadAadhaar() string { return g.aadhaar(false) }

func (g *Gen) aadhaar(valid bool) string {
	body := strconv.Itoa(2+g.R.IntN(8)) + g.digits(10)
	c := detect.VerhoeffCheckDigit(body)
	if !valid {
		c = '0' + (c-'0'+1+byte(g.R.IntN(8)))%10
	}
	d := body + string(c)
	return d[:4] + " " + d[4:8] + " " + d[8:]
}

// SpanishID returns a valid DNI or NIE.
func (g *Gen) SpanishID() string {
	if g.R.IntN(3) == 0 {
		p := g.R.IntN(3)
		num := g.digits(7)
		n, _ := strconv.Atoi(strconv.Itoa(p) + num)
		return string("XYZ"[p]) + num + string(detect.DNILetter(n))
	}
	num := g.digits(8)
	n, _ := strconv.Atoi(num)
	return num + string(detect.DNILetter(n))
}

// ChineseRIC returns a valid 18-character resident ID.
func (g *Gen) ChineseRIC() string {
	region := strconv.Itoa(11+g.R.IntN(54)) + g.digits(4)
	birth := fmt.Sprintf("%04d%02d%02d", 1950+g.R.IntN(55), 1+g.R.IntN(12), 1+g.R.IntN(28))
	first := region + birth + g.digits(3)
	return first + string(detect.RICCheckChar(first))
}

// AWSKey returns an AWS access key ID.
func (g *Gen) AWSKey() string {
	return []string{"AKIA", "ASIA"}[g.R.IntN(2)] + g.charsFrom(upperDigits, 16)
}

// GitHubToken returns a classic personal access token.
func (g *Gen) GitHubToken() string { return "ghp_" + g.charsFrom(alnum, 36) }

// SlackToken returns a bot token.
func (g *Gen) SlackToken() string {
	return "xoxb-" + g.digits(11) + "-" + g.digits(12) + "-" + g.charsFrom(alnum, 24)
}

// StripeKey returns a live secret key.
func (g *Gen) StripeKey() string {
	return []string{"sk_live_", "rk_live_", "sk_test_"}[g.R.IntN(3)] + g.charsFrom(alnum, 24)
}

// GoogleKey returns a Google API key.
func (g *Gen) GoogleKey() string { return "AIza" + g.charsFrom(b64url, 35) }

// LLMKey returns an OpenAI- or Anthropic-style key.
func (g *Gen) LLMKey() string {
	if g.R.IntN(2) == 0 {
		return "sk-proj-" + g.charsFrom(alnum, 48)
	}
	return "sk-ant-api03-" + g.charsFrom(b64url, 80)
}

// JWT returns a syntactically valid HS256 token with a random signature.
func (g *Gen) JWT() string {
	enc := base64.RawURLEncoding
	hdr := enc.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload := enc.EncodeToString([]byte(fmt.Sprintf(`{"sub":"%s","uid":%d}`, g.pick(g.Vocab.First), g.R.IntN(1_000_000))))
	return hdr + "." + payload + "." + g.charsFrom(b64url, 43)
}

// PrivateKeyHeader returns a PEM private key header.
func (g *Gen) PrivateKeyHeader() string {
	return "-----BEGIN " + []string{"RSA ", "EC ", "OPENSSH ", ""}[g.R.IntN(4)] + "PRIVATE KEY-----"
}

// Password returns a mixed-class password value.
func (g *Gen) Password() string {
	return g.charsFrom("abcdefghijkmnopqrstuvwxyz", 5) + g.digits(2) + g.charsFrom("!@#%&*", 1) + g.charsFrom("ABCDEFGHJKLMNPQRSTUVWXYZ", 2)
}

// EntropyToken returns a random base64 secret (e.g. a cloud secret key).
func (g *Gen) EntropyToken() string { return g.charsFrom(b64chars, 40) }

// GitSHA returns a 40-char hex digest (benign high-entropy-looking string).
func (g *Gen) GitSHA() string { return g.charsFrom("0123456789abcdef", 40) }

// UUID returns a random UUID string.
func (g *Gen) UUID() string {
	h := g.charsFrom("0123456789abcdef", 32)
	return h[:8] + "-" + h[8:12] + "-4" + h[13:16] + "-a" + h[17:20] + "-" + h[20:]
}

// Benign returns a value that resembles sensitive data but is not
// (dates, IPs, versions, order numbers, ISBNs, hashes, identifiers...).
func (g *Gen) Benign() string {
	switch g.R.IntN(14) {
	case 0:
		return fmt.Sprintf("%04d-%02d-%02d", 2015+g.R.IntN(11), 1+g.R.IntN(12), 1+g.R.IntN(28))
	case 1:
		return fmt.Sprintf("%d.%d.%d.%d", 10+g.R.IntN(240), g.R.IntN(256), g.R.IntN(256), g.R.IntN(256))
	case 2:
		return fmt.Sprintf("v%d.%d.%d", g.R.IntN(5), g.R.IntN(30), g.R.IntN(200))
	case 3:
		return "ORD-" + strconv.Itoa(2020+g.R.IntN(6)) + "-" + g.digits(6)
	case 4:
		return "978-" + g.digits(1) + "-" + g.digits(2) + "-" + g.digits(6) + "-" + g.digits(1)
	case 5:
		return g.GitSHA()
	case 6:
		return g.UUID()
	case 7:
		return fmt.Sprintf("$%d,%03d.%02d", 1+g.R.IntN(99), g.R.IntN(1000), g.R.IntN(100))
	case 8:
		return "get" + []string{"User", "Account", "Order"}[g.R.IntN(3)] + "By" + []string{"Id", "Email", "Name"}[g.R.IntN(3)] + "Handler"
	case 9:
		return g.BadCard()
	case 10:
		return g.BadIBAN()
	case 11:
		return g.BadSSN()
	case 12:
		return g.BadAadhaar()
	default:
		return fmt.Sprintf("%02d:%02d:%02d", g.R.IntN(24), g.R.IntN(60), g.R.IntN(60))
	}
}

// Value generates a positive value for kind k.
func (g *Gen) Value(k detect.Kind) string {
	switch k {
	case detect.KindEmail:
		return g.Email()
	case detect.KindPhone:
		return g.Phone()
	case detect.KindCreditCard:
		return g.Card()
	case detect.KindIBAN:
		return g.IBAN()
	case detect.KindUSSSN:
		return g.SSN()
	case detect.KindAadhaar:
		return g.Aadhaar()
	case detect.KindSpanishID:
		return g.SpanishID()
	case detect.KindChineseRIC:
		return g.ChineseRIC()
	case detect.KindAWSAccessKey:
		return g.AWSKey()
	case detect.KindGitHubToken:
		return g.GitHubToken()
	case detect.KindSlackToken:
		return g.SlackToken()
	case detect.KindStripeKey:
		return g.StripeKey()
	case detect.KindGoogleAPIKey:
		return g.GoogleKey()
	case detect.KindLLMAPIKey:
		return g.LLMKey()
	case detect.KindJWT:
		return g.JWT()
	case detect.KindPrivateKey:
		return g.PrivateKeyHeader()
	case detect.KindCredentialPair:
		return g.Password()
	case detect.KindHighEntropy:
		return g.EntropyToken()
	}
	panic("corpus: no generator for kind " + string(k))
}
