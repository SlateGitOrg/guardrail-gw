package detect

import "strings"

// digitsOnly returns the ASCII digits of s in order.
func digitsOnly(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// Luhn reports whether the digit string passes the Luhn (mod 10) check used
// by payment card numbers. Non-digit input returns false.
func Luhn(digits string) bool {
	if len(digits) < 2 {
		return false
	}
	sum := 0
	double := false
	for i := len(digits) - 1; i >= 0; i-- {
		c := digits[i]
		if !isDigit(c) {
			return false
		}
		d := int(c - '0')
		if double {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
}

// IBANValid reports whether an IBAN (spaces allowed) passes the ISO 13616
// mod-97 check and has the registered length for its country.
func IBANValid(raw string) bool {
	s := strings.ReplaceAll(raw, " ", "")
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	want, ok := ibanLengths[s[:2]]
	if !ok || want != len(s) {
		return false
	}
	if !isDigit(s[2]) || !isDigit(s[3]) {
		return false
	}
	return mod97(s[4:]+s[:4]) == 1
}

// mod97 computes the IBAN remainder, mapping letters A..Z to 10..35.
func mod97(s string) int {
	r := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isDigit(c):
			r = (r*10 + int(c-'0')) % 97
		case c >= 'A' && c <= 'Z':
			v := int(c-'A') + 10
			r = (r*100 + v) % 97
		default:
			return -1
		}
	}
	return r
}

// ibanLengths holds the registered IBAN length per country (subset of the
// SWIFT IBAN registry covering the most common countries).
var ibanLengths = map[string]int{
	"AD": 24, "AE": 23, "AT": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "CH": 21,
	"CY": 28, "CZ": 24, "DE": 22, "DK": 18, "EE": 20, "ES": 24, "FI": 18, "FR": 27,
	"GB": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27,
	"KW": 30, "KZ": 20, "LI": 21, "LT": 20, "LU": 20, "LV": 21, "MC": 27, "MT": 31,
	"NL": 18, "NO": 15, "PK": 24, "PL": 28, "PT": 25, "QA": 29, "RO": 24, "RS": 22,
	"SA": 24, "SE": 24, "SI": 19, "SK": 24, "SM": 27, "TR": 26, "UA": 29,
}

// IBANLength returns the registered IBAN length for a country code.
func IBANLength(country string) (int, bool) {
	n, ok := ibanLengths[country]
	return n, ok
}

// Verhoeff tables (dihedral group D5) used by India's Aadhaar numbers.
var (
	verhoeffD = [10][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 2, 3, 4, 0, 6, 7, 8, 9, 5},
		{2, 3, 4, 0, 1, 7, 8, 9, 5, 6}, {3, 4, 0, 1, 2, 8, 9, 5, 6, 7},
		{4, 0, 1, 2, 3, 9, 5, 6, 7, 8}, {5, 9, 8, 7, 6, 0, 4, 3, 2, 1},
		{6, 5, 9, 8, 7, 1, 0, 4, 3, 2}, {7, 6, 5, 9, 8, 2, 1, 0, 4, 3},
		{8, 7, 6, 5, 9, 3, 2, 1, 0, 4}, {9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}
	verhoeffP = [8][10]int{
		{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}, {1, 5, 7, 6, 2, 8, 3, 0, 9, 4},
		{5, 8, 0, 3, 7, 9, 6, 1, 4, 2}, {8, 9, 1, 6, 0, 4, 3, 5, 2, 7},
		{9, 4, 5, 3, 1, 2, 6, 8, 7, 0}, {4, 2, 8, 6, 5, 7, 3, 9, 0, 1},
		{2, 7, 9, 3, 8, 0, 6, 4, 1, 5}, {7, 0, 4, 6, 9, 1, 3, 2, 5, 8},
	}
	verhoeffInv = [10]int{0, 4, 3, 2, 1, 5, 6, 7, 8, 9}
)

// Verhoeff reports whether the digit string carries a valid Verhoeff check digit.
func Verhoeff(digits string) bool {
	if digits == "" {
		return false
	}
	c := 0
	for i := 0; i < len(digits); i++ {
		ch := digits[len(digits)-1-i]
		if !isDigit(ch) {
			return false
		}
		c = verhoeffD[c][verhoeffP[i%8][int(ch-'0')]]
	}
	return c == 0
}

// VerhoeffCheckDigit computes the check digit to append to digits.
func VerhoeffCheckDigit(digits string) byte {
	c := 0
	for i := 0; i < len(digits); i++ {
		ch := digits[len(digits)-1-i]
		c = verhoeffD[c][verhoeffP[(i+1)%8][int(ch-'0')]]
	}
	return byte('0' + verhoeffInv[c])
}

const dniLetters = "TRWAGMYFPDXBNJZSQVHLCKE"

// DNILetter returns the Spanish DNI/NIE control letter for the numeric part.
func DNILetter(n int) byte { return dniLetters[n%23] }

// SpanishIDValid validates a Spanish DNI (8 digits + letter) or NIE
// (X/Y/Z + 7 digits + letter); an optional hyphen before the letter or after
// the NIE prefix is ignored.
func SpanishIDValid(raw string) bool {
	s := strings.ReplaceAll(raw, "-", "")
	if len(s) != 9 {
		return false
	}
	switch s[0] {
	case 'X':
		s = "0" + s[1:]
	case 'Y':
		s = "1" + s[1:]
	case 'Z':
		s = "2" + s[1:]
	}
	n := 0
	for i := 0; i < 8; i++ {
		if !isDigit(s[i]) {
			return false
		}
		n = n*10 + int(s[i]-'0')
	}
	return s[8] == DNILetter(n)
}

// ChineseRICValid validates an 18-character PRC Resident Identity Card number
// using the ISO 7064 MOD 11-2 check character and a plausible birth date.
func ChineseRICValid(s string) bool {
	if len(s) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		if !isDigit(s[i]) {
			return false
		}
		sum += int(s[i]-'0') * ricWeights[i]
	}
	check := "10X98765432"[sum%11]
	last := s[17]
	if last == 'x' {
		last = 'X'
	}
	if last != check {
		return false
	}
	return plausibleDate(s[6:14])
}

var ricWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}

// RICCheckChar computes the check character for the first 17 digits.
func RICCheckChar(first17 string) byte {
	sum := 0
	for i := 0; i < 17; i++ {
		sum += int(first17[i]-'0') * ricWeights[i]
	}
	return "10X98765432"[sum%11]
}

func plausibleDate(yyyymmdd string) bool {
	atoi := func(s string) int {
		n := 0
		for i := 0; i < len(s); i++ {
			n = n*10 + int(s[i]-'0')
		}
		return n
	}
	y, m, d := atoi(yyyymmdd[:4]), atoi(yyyymmdd[4:6]), atoi(yyyymmdd[6:8])
	return y >= 1900 && y <= 2099 && m >= 1 && m <= 12 && d >= 1 && d <= 31
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isUpper(c byte) bool { return c >= 'A' && c <= 'Z' }
func isLower(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlpha(c byte) bool { return isUpper(c) || isLower(c) }
func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }
