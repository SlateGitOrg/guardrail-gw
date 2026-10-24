package detect

import (
	"strings"
)

// keywordWindow is how far back (bytes) context keywords are searched.
const keywordWindow = 40

// hasKeywordBefore reports whether any keyword occurs (case-insensitively) in
// the window of text immediately before s.
func hasKeywordBefore(text string, s int, keywords ...string) bool {
	lo := max(0, s-keywordWindow)
	window := strings.ToLower(text[lo:s])
	for _, k := range keywords {
		if strings.Contains(window, k) {
			return true
		}
	}
	return false
}

// NewEmail detects RFC 5321-style addresses with a dotted domain and an
// alphabetic top-level domain.
func NewEmail() (Detector, error) {
	const expr = `[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9\-]{1,63}(?:\.[A-Za-z0-9\-]{1,63}){1,4}`
	isLocal := func(c byte) bool { return isAlnum(c) || strings.IndexByte("._%+-", c) >= 0 }
	return newPattern(KindEmail, CategoryPII, 60, 1, expr, func(text string, s, e int) (int, bool) {
		if isAlnum(byteAt(text, e)) || byteAt(text, e) == '-' {
			return 0, false
		}
		m := text[s:e]
		at := strings.IndexByte(m, '@')
		local, domain := m[:at], m[at+1:]
		if local[0] == '.' || local[len(local)-1] == '.' || strings.Contains(local, "..") {
			return 0, false
		}
		labels := strings.Split(domain, ".")
		for _, l := range labels {
			if l[0] == '-' || l[len(l)-1] == '-' {
				return 0, false
			}
		}
		tld := labels[len(labels)-1]
		if len(tld) < 2 {
			return 0, false
		}
		for i := 0; i < len(tld); i++ {
			if !isAlpha(tld[i]) {
				return 0, false
			}
		}
		return e, true
	}, need('@'), leftCheck(func(text string, s int) bool { return !isLocal(byteAt(text, s-1)) }))
}

var phoneKeywords = []string{"call", "phone", "tel", "mobile", "cell", "contact", "text", "whatsapp", "fax", "dial", "reach"}

// NewPhone detects international (+CC) and North American phone numbers, plus
// leading-zero national formats with separators.
func NewPhone() (Detector, error) {
	const expr = `(?:\+[0-9]{1,3}[ .\-]?)?(?:\([0-9]{1,4}\)[ .\-]?)?[0-9]{2,12}(?:[ .\-][0-9]{2,8}){0,4}`
	return newPattern(KindPhone, CategoryPII, 50, keywordWindow, expr, func(text string, s, e int) (int, bool) {
		if !rightNumericBoundary(text, e) {
			return 0, false
		}
		return e, validPhone(text, s, e)
	}, leftCheck(leftNumericBoundary), lookahead(" -."))
}

func validPhone(text string, s, e int) bool {
	m := text[s:e]
	digits := digitsOnly(m)
	hasPlus := m[0] == '+'
	hasParens := strings.IndexByte(m, '(') >= 0
	seps := separators(m)
	if strings.IndexByte(seps, '.') >= 0 {
		// Dotted forms collide with IPs and versions: only allow NANP 3.3.4.
		if len(seps) > 1 {
			return false
		}
		groups := strings.Split(strings.TrimPrefix(strings.TrimPrefix(m, "+1"), "."), ".")
		if len(groups) != 3 || len(groups[0]) != 3 || len(groups[1]) != 3 || len(groups[2]) != 4 {
			return false
		}
		return nanp(digitsOnly(strings.Join(groups, "")))
	}
	groups := digitGroups(m)
	switch {
	case hasPlus:
		return len(digits) >= 8 && len(digits) <= 15 && digits[0] != '0'
	case len(digits) == 10 && nanp(digits):
		if seps == "" && !hasParens {
			return hasKeywordBefore(text, s, phoneKeywords...)
		}
		return sameInts(groups, 3, 3, 4)
	case len(digits) == 11 && digits[0] == '1' && nanp(digits[1:]):
		if seps == "" {
			return hasKeywordBefore(text, s, phoneKeywords...)
		}
		return sameInts(groups, 1, 3, 3, 4)
	case (len(digits) == 10 || len(digits) == 11) && digits[0] == '0':
		// National trunk-prefix formats such as "020 7946 0958".
		if len(groups) < 2 || len(groups[0]) < 2 || len(groups[0]) > 5 {
			return false
		}
		for _, g := range groups[1:] {
			if len(g) < 3 || len(g) > 4 {
				return false
			}
		}
		return true
	}
	return false
}

// digitGroups splits a phone candidate into its runs of digits.
func digitGroups(m string) []string {
	return strings.FieldsFunc(m, func(r rune) bool { return r < '0' || r > '9' })
}

func sameInts(groups []string, want ...int) bool {
	if len(groups) != len(want) {
		return false
	}
	for i, g := range groups {
		if len(g) != want[i] {
			return false
		}
	}
	return true
}

// nanp validates a 10-digit North American number: area code and exchange
// must not start with 0 or 1.
func nanp(d string) bool {
	return len(d) == 10 && d[0] >= '2' && d[3] >= '2'
}

// NewCreditCard detects 13-19 digit payment card numbers that pass Luhn and
// match a known issuer prefix and length.
func NewCreditCard() (Detector, error) {
	const expr = `[0-9](?:[ \-]?[0-9]){12,18}`
	return newPattern(KindCreditCard, CategoryPII, 70, 2, expr, func(text string, s, e int) (int, bool) {
		// Try the longest digit-aligned prefix first; a card may be followed
		// by another number group ("4111 1111 1111 1111 2026").
		for end := e; end-s >= 13; end-- {
			if !isDigit(text[end-1]) || isAlnum(byteAt(text, end)) {
				continue
			}
			m := text[s:end]
			if len(separators(m)) > 1 {
				continue
			}
			d := digitsOnly(m)
			if len(d) < 13 {
				break
			}
			if Luhn(d) && issuerMatches(d) {
				return end, true
			}
		}
		return 0, false
	}, leftCheck(leftNumericBoundary), lookahead(" -."))
}

// issuerMatches checks the IIN prefix and length against major card brands.
func issuerMatches(d string) bool {
	n := len(d)
	p2 := atoiPrefix(d, 2)
	p3 := atoiPrefix(d, 3)
	p4 := atoiPrefix(d, 4)
	switch {
	case d[0] == '4':
		return n == 13 || n == 16 || n == 19
	case p2 >= 51 && p2 <= 55, p4 >= 2221 && p4 <= 2720:
		return n == 16
	case p2 == 34 || p2 == 37:
		return n == 15
	case p4 == 6011, p2 == 65, p3 >= 644 && p3 <= 649:
		return n >= 16 && n <= 19
	case p4 >= 3528 && p4 <= 3589:
		return n >= 16 && n <= 19
	case p3 >= 300 && p3 <= 305, p2 == 36, p2 == 38, p2 == 39:
		return n >= 14 && n <= 19
	case p2 == 62:
		return n >= 16 && n <= 19
	}
	return false
}

func atoiPrefix(d string, k int) int {
	n := 0
	for i := 0; i < k && i < len(d); i++ {
		n = n*10 + int(d[i]-'0')
	}
	return n
}

// NewIBAN detects International Bank Account Numbers (compact or grouped by
// single spaces) with a registered country length and a valid mod-97 check.
func NewIBAN() (Detector, error) {
	const expr = `[A-Z]{2}[0-9]{2}(?: ?[A-Z0-9]){11,30}`
	return newPattern(KindIBAN, CategoryPII, 68, 1, expr, func(text string, s, e int) (int, bool) {
		want, ok := IBANLength(text[s : s+2])
		if !ok {
			return 0, false
		}
		// Walk exactly `want` alphanumerics, allowing single spaces between.
		count, end := 0, s
		for end < e && count < want {
			if text[end] != ' ' {
				count++
			}
			end++
		}
		if count != want || !rightWordBoundary(text, end) {
			return 0, false
		}
		return end, IBANValid(text[s:end])
	}, leftCheck(leftWordBoundary))
}

var ssnKeywords = []string{"ssn", "social security", "ss#", "soc sec"}

// NewUSSSN detects US Social Security Numbers. SSNs carry no check digit, so
// validity uses the SSA structural rules (area not 000/666/9xx, group not 00,
// serial not 0000); undashed forms additionally require a nearby keyword.
func NewUSSSN() (Detector, error) {
	const expr = `[0-9]{3}[\- ]?[0-9]{2}[\- ]?[0-9]{4}`
	return newPattern(KindUSSSN, CategoryPII, 65, keywordWindow, expr, func(text string, s, e int) (int, bool) {
		if !rightNumericBoundary(text, e) {
			return 0, false
		}
		m := text[s:e]
		seps := separators(m)
		if len(seps) > 1 || (seps != "" && len(m) != 11) {
			return 0, false
		}
		d := digitsOnly(m)
		area, group, serial := d[:3], d[3:5], d[5:]
		if area == "000" || area == "666" || area[0] == '9' || group == "00" || serial == "0000" {
			return 0, false
		}
		if seps != "-" && !hasKeywordBefore(text, s, ssnKeywords...) {
			return 0, false
		}
		return e, true
	}, leftCheck(leftNumericBoundary), lookahead(" -."))
}

var aadhaarKeywords = []string{"aadhaar", "aadhar", "uidai", "uid"}

// NewAadhaar detects Indian Aadhaar numbers: 12 digits, first digit 2-9, valid
// Verhoeff check digit. Unseparated forms require a nearby keyword.
func NewAadhaar() (Detector, error) {
	const expr = `[2-9][0-9]{3}[ \-]?[0-9]{4}[ \-]?[0-9]{4}`
	return newPattern(KindAadhaar, CategoryPII, 65, keywordWindow, expr, func(text string, s, e int) (int, bool) {
		if !rightNumericBoundary(text, e) {
			return 0, false
		}
		m := text[s:e]
		seps := separators(m)
		if len(seps) > 1 || (seps != "" && len(m) != 14) {
			return 0, false
		}
		if !Verhoeff(digitsOnly(m)) {
			return 0, false
		}
		if seps == "" && !hasKeywordBefore(text, s, aadhaarKeywords...) {
			return 0, false
		}
		return e, true
	}, leftCheck(leftNumericBoundary), lookahead(" -."))
}

// NewSpanishID detects Spanish DNI and NIE numbers with a valid mod-23 letter.
func NewSpanishID() (Detector, error) {
	const expr = `(?:[XYZ]-?[0-9]{7}|[0-9]{8})-?[A-Z]`
	return newPattern(KindSpanishID, CategoryPII, 65, 1, expr, func(text string, s, e int) (int, bool) {
		if !rightWordBoundary(text, e) {
			return 0, false
		}
		return e, SpanishIDValid(text[s:e])
	}, leftCheck(leftWordBoundary))
}

// NewChineseRIC detects 18-character PRC Resident Identity Card numbers with a
// valid ISO 7064 MOD 11-2 check character and plausible birth date.
func NewChineseRIC() (Detector, error) {
	const expr = `[1-9][0-9]{16}[0-9Xx]`
	return newPattern(KindChineseRIC, CategoryPII, 65, 1, expr, func(text string, s, e int) (int, bool) {
		if !rightWordBoundary(text, e) {
			return 0, false
		}
		return e, ChineseRICValid(text[s:e])
	}, leftCheck(leftWordBoundary))
}
