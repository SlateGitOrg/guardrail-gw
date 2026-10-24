package detect

import (
	"errors"
	"strings"
	"testing"
)

func mustSet(t *testing.T) *Set {
	t.Helper()
	s, err := NewSet(Options{})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestChecksums(t *testing.T) {
	cases := []struct {
		name string
		fn   func(string) bool
		in   string
		want bool
	}{
		{"luhn visa", Luhn, "4111111111111111", true},
		{"luhn bad", Luhn, "4111111111111112", false},
		{"luhn short", Luhn, "4", false},
		{"luhn nondigit", Luhn, "41a1", false},
		{"iban gb", IBANValid, "GB82WEST12345698765432", true},
		{"iban de spaced", IBANValid, "DE89 3704 0044 0532 0130 00", true},
		{"iban bad check", IBANValid, "GB82WEST12345698765433", false},
		{"iban wrong len", IBANValid, "GB82WEST1234569876543", false},
		{"iban unknown cc", IBANValid, "ZZ82WEST12345698765432", false},
		{"verhoeff", Verhoeff, "2363", true},
		{"verhoeff bad", Verhoeff, "2364", false},
		{"verhoeff empty", Verhoeff, "", false},
		{"dni", SpanishIDValid, "12345678Z", true},
		{"dni hyphen", SpanishIDValid, "12345678-Z", true},
		{"dni bad", SpanishIDValid, "12345678A", false},
		{"nie", SpanishIDValid, "X1234567L", true},
		{"nie y", SpanishIDValid, "Y1234567X", true},
		{"ric", ChineseRICValid, "11010519491231002X", true},
		{"ric lower x", ChineseRICValid, "11010519491231002x", true},
		{"ric bad check", ChineseRICValid, "110105194912310021", false},
		{"ric bad date", ChineseRICValid, "110105194913310021", false},
	}
	for _, c := range cases {
		if got := c.fn(c.in); got != c.want {
			t.Errorf("%s(%q)=%v want %v", c.name, c.in, got, c.want)
		}
	}
	if d := VerhoeffCheckDigit("236"); d != '3' {
		t.Errorf("VerhoeffCheckDigit=%c", d)
	}
	if c := RICCheckChar("11010519491231002"); c != 'X' {
		t.Errorf("RICCheckChar=%c", c)
	}
}

func TestAnalyzePattern(t *testing.T) {
	info, err := AnalyzePattern(`ab[0-9]{2,4}(?:x|yz)?`)
	if err != nil {
		t.Fatal(err)
	}
	if info.MaxLen != 2+4+2 {
		t.Errorf("MaxLen=%d", info.MaxLen)
	}
	for _, b := range []byte("ab0189xyz") {
		if !info.Alphabet.Contains(b) {
			t.Errorf("alphabet missing %q", b)
		}
	}
	if info.Alphabet.Contains('c') {
		t.Error("alphabet has c")
	}
	fold, err := AnalyzePattern(`(?i)k`)
	if err != nil || !fold.Alphabet.Contains('K') || !fold.Alphabet.Contains('k') {
		t.Errorf("fold-case alphabet wrong: %v", err)
	}
	for expr, want := range map[string]error{
		`a+`:     ErrUnboundedPattern,
		`a*`:     ErrUnboundedPattern,
		`a{2,}`:  ErrUnboundedPattern,
		`^a`:     ErrAnchoredPattern,
		`a$`:     ErrAnchoredPattern,
		`\ba`:    ErrAnchoredPattern,
		`a\B`:    ErrAnchoredPattern,
		`(?s).`:  nil,
		`[^a]`:   nil,
		`é{1,2}`: nil,
	} {
		_, err := AnalyzePattern(expr)
		if !errors.Is(err, want) {
			t.Errorf("%q: err=%v want %v", expr, err, want)
		}
	}
	if _, err := AnalyzePattern(`(`); err == nil {
		t.Error("expected parse error")
	}
}

func TestEveryDetectorBounded(t *testing.T) {
	for _, d := range mustSet(t).Detectors() {
		if d.MaxLen() <= 0 || d.MaxLen() > 8192 {
			t.Errorf("%s: MaxLen=%d", d.Kind(), d.MaxLen())
		}
		if d.LeftContext() < 0 || d.LeftContext() > 64 {
			t.Errorf("%s: LeftContext=%d", d.Kind(), d.LeftContext())
		}
		if _, ok := CategoryOf(d.Kind()); !ok {
			t.Errorf("%s: no category", d.Kind())
		}
	}
}

type tc struct {
	text  string
	match string // "" = expect no match of this kind
}

func checkKind(t *testing.T, k Kind, cases []tc) {
	t.Helper()
	d, ok := mustSet(t).Get(k)
	if !ok {
		t.Fatalf("no detector %s", k)
	}
	for _, c := range cases {
		got := FindAll(d, c.text)
		if c.match == "" {
			if len(got) != 0 {
				t.Errorf("%s: %q: unexpected match %q", k, c.text, c.text[got[0].Start:got[0].End])
			}
			continue
		}
		if len(got) != 1 || c.text[got[0].Start:got[0].End] != c.match {
			var ms []string
			for _, f := range got {
				ms = append(ms, c.text[f.Start:f.End])
			}
			t.Errorf("%s: %q: got %q want %q", k, c.text, ms, c.match)
		}
	}
}

func TestEmail(t *testing.T) {
	checkKind(t, KindEmail, []tc{
		{"mail jane.doe+tag@example.co.uk now", "jane.doe+tag@example.co.uk"},
		{"end with dot a.b@example.com.", "a.b@example.com"},
		{"no tld x@localhost", ""},
		{"numeric tld x@host.c0m", ""},
		{"double dot a..b@ex.com", ""},
		{"leading dot .ab@ex.com", ""},
		{"hyphen label a@-ex.com", ""},
		{"version pkg@1.2.3", ""},
	})
}

func TestPhone(t *testing.T) {
	checkKind(t, KindPhone, []tc{
		{"call +1 415-555-0132 today", "+1 415-555-0132"},
		{"office (415) 555-0132.", "(415) 555-0132"},
		{"uk +44 20 7946 0958", "+44 20 7946 0958"},
		{"in +91 98765 43210", "+91 98765 43210"},
		{"dotted 415.555.0132", "415.555.0132"},
		{"national 020 7946 0958", "020 7946 0958"},
		{"call me 4155550132", "4155550132"},
		{"order 4155550132", ""},
		{"ip 192.168.100.200", ""},
		{"date 2024-01-15", ""},
		{"version 10.12.155", ""},
		{"bad area (115) 555-0132", ""},
		{"card 4111 1111 1111 1111", ""},
	})
}

func TestCreditCard(t *testing.T) {
	checkKind(t, KindCreditCard, []tc{
		{"visa 4111 1111 1111 1111 exp", "4111 1111 1111 1111"},
		{"compact 5555555555554444.", "5555555555554444"},
		{"amex 3782-822463-10005", "3782-822463-10005"},
		{"followed 4111 1111 1111 1111 2026", "4111 1111 1111 1111"},
		{"luhn fail 4111 1111 1111 1112", ""},
		{"unknown iin 9111111111111111", ""},
		{"mixed seps 4111-1111 1111 1111", ""},
		{"embedded x4111111111111111", ""},
		{"too long 41111111111111111111111", ""},
	})
}

func TestIBAN(t *testing.T) {
	checkKind(t, KindIBAN, []tc{
		{"pay GB82WEST12345698765432 now", "GB82WEST12345698765432"},
		{"pay DE89 3704 0044 0532 0130 00 BIC COBADEFF", "DE89 3704 0044 0532 0130 00"},
		{"bad GB82WEST12345698765433", ""},
		{"lower gb82west12345698765432", ""},
	})
}

func TestNationalIDs(t *testing.T) {
	checkKind(t, KindUSSSN, []tc{
		{"id 123-45-6789", "123-45-6789"},
		{"ssn 123456789", "123456789"},
		{"num 123456789", ""},
		{"area 000-45-6789", ""},
		{"area 666-45-6789", ""},
		{"area 900-45-6789", ""},
		{"group 123-00-6789", ""},
		{"serial 123-45-0000", ""},
		{"mixed 123-45 6789", ""},
		{"longer 123-45-6789-1", ""},
	})
	aad := "2345 6789 012" + string(VerhoeffCheckDigit("23456789012"))
	checkKind(t, KindAadhaar, []tc{
		{"card " + aad, aad},
		{"aadhaar " + strings.ReplaceAll(aad, " ", ""), strings.ReplaceAll(aad, " ", "")},
		{"num " + strings.ReplaceAll(aad, " ", ""), ""},
		{"bad 2345 6789 0120", nonEmptyIf(Verhoeff("234567890120"), "2345 6789 0120")},
	})
	checkKind(t, KindSpanishID, []tc{
		{"dni 12345678Z.", "12345678Z"},
		{"nie X1234567L", "X1234567L"},
		{"bad 12345678A", ""},
	})
	checkKind(t, KindChineseRIC, []tc{
		{"ric 11010519491231002X ok", "11010519491231002X"},
		{"bad 110105194912310021", ""},
	})
}

func nonEmptyIf(cond bool, s string) string {
	if cond {
		return s
	}
	return ""
}

func TestSecrets(t *testing.T) {
	checkKind(t, KindAWSAccessKey, []tc{
		{"key AKIAIOSFODNN7EXAMPLE end", "AKIAIOSFODNN7EXAMPLE"},
		{"xAKIAIOSFODNN7EXAMPLE", ""},
	})
	gh := "ghp_" + strings.Repeat("aB3", 12)
	checkKind(t, KindGitHubToken, []tc{{"token " + gh, gh}, {"ghp_short", ""}})
	checkKind(t, KindSlackToken, []tc{{"xoxb-1234567890-abcdefABCDEF", "xoxb-1234567890-abcdefABCDEF"}})
	checkKind(t, KindStripeKey, []tc{{"sk_live_4eC39HqLyjWDarjtT1zdp7dc", "sk_live_4eC39HqLyjWDarjtT1zdp7dc"}})
	g := "AIza" + strings.Repeat("Sy9_", 8) + "abc"
	checkKind(t, KindGoogleAPIKey, []tc{{"g=" + g, g}})
	checkKind(t, KindLLMAPIKey, []tc{
		{"OPENAI sk-proj-Ab3dEf9hIjK2mNoP5qRsT7uVwX", "sk-proj-Ab3dEf9hIjK2mNoP5qRsT7uVwX"},
		{"sk-ant-api03-Zx8yW7vU6tS5rQ4pO3nM2lK1", "sk-ant-api03-Zx8yW7vU6tS5rQ4pO3nM2lK1"},
		{"task-learning-is-fun-and-easy-ok", ""},
		{"sk-aaaaaaaaaaaaaaaaaaaaaaaa", ""},
	})
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
	checkKind(t, KindJWT, []tc{{"Bearer " + jwt + ".", jwt}, {"eyJub3QganNvbg.eyJhYmMiOjF9.x", ""}})
	checkKind(t, KindPrivateKey, []tc{
		{"-----BEGIN RSA PRIVATE KEY-----\nMII", "-----BEGIN RSA PRIVATE KEY-----"},
		{"-----BEGIN PUBLIC KEY-----", ""},
	})
	checkKind(t, KindCredentialPair, []tc{
		{"password: hunter2!", "hunter2!"},
		{`API_KEY="Zx81_kk-29"`, "Zx81_kk-29"},
		{"db_password = s3cretValue.", "s3cretValue"},
		{"password: $DB_PASS", ""},
		{"password: ********", ""},
		{"password: required", ""},
		{"the password is hunter2", ""},
	})
}

func TestHighEntropy(t *testing.T) {
	checkKind(t, KindHighEntropy, []tc{
		{"blob wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY end", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
		{"commit 3f786850e387550fdab836ed7e6dc881de23001b", ""},
		{"secret: 3f786850e387550fdab836ed7e6dc881de23001b", "3f786850e387550fdab836ed7e6dc881de23001b"},
		{"identifier getUserAccountSettingsHandler", ""},
		{"words state-of-the-art-machine-learning-model", ""},
		{"uuid 123e4567-e89b-12d3-a456-426614174000", ""},
		{"long " + strings.Repeat("aB3dE9", 100), ""},
		{"short Ab3dE9", ""},
	})
}

func TestScanAllSorted(t *testing.T) {
	text := "email a@b.io card 4111111111111111 key AKIAIOSFODNN7EXAMPLE"
	f := mustSet(t).ScanAll(text)
	for i := 1; i < len(f); i++ {
		if f[i].Start < f[i-1].Start {
			t.Fatalf("not sorted: %+v", f)
		}
	}
	kinds := map[Kind]bool{}
	for _, x := range f {
		kinds[x.Kind] = true
	}
	for _, k := range []Kind{KindEmail, KindCreditCard, KindAWSAccessKey} {
		if !kinds[k] {
			t.Errorf("missing %s in %+v", k, f)
		}
	}
}

func TestSetOptions(t *testing.T) {
	s, err := NewSet(Options{Disabled: map[Kind]bool{KindEmail: true}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Get(KindEmail); ok {
		t.Error("email should be disabled")
	}
	if len(s.Select(func(d Detector) bool { return d.Category() == CategoryPII })) != 7 {
		t.Error("expected 7 PII detectors")
	}
	if _, err := NewSet(Options{Entropy: EntropyConfig{MinLen: 30, MaxLen: 10}}); err == nil {
		t.Error("expected entropy config error")
	}
	if len(AllKinds()) != 18 {
		t.Errorf("AllKinds=%d", len(AllKinds()))
	}
	if _, ok := CategoryOf("nope"); ok {
		t.Error("unknown kind has category")
	}
}

func TestFirstBytes(t *testing.T) {
	info, err := AnalyzePattern(`(?:\+[0-9])?(?:ab|[xy]z)?k{0,2}Q`)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range []byte("+axykQ") {
		if !info.First.Contains(b) {
			t.Errorf("first missing %q", b)
		}
	}
	for _, b := range []byte("0bz") {
		if info.First.Contains(b) {
			t.Errorf("first wrongly has %q", b)
		}
	}
	fold, _ := AnalyzePattern(`(?i)s`)
	if !fold.First.Contains('S') || !fold.First.Contains('s') {
		t.Error("fold-case first set")
	}
	any, _ := AnalyzePattern(`(?s).a`)
	if !any.First.Contains('\n') {
		t.Error("any-char first set")
	}
}
