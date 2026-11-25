package pocverify

import (
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Value is a parsed JSON value. Objects keep their members (duplicates are
// rejected by the parser); numbers keep the exact text they were written as.
type Value struct {
	Kind    Kind
	Str     string   // KindString
	Num     string   // KindNumber: the literal as written
	Bool    bool     // KindBool
	Members []Member // KindObject, in input order
	Items   []Value  // KindArray
}

// Member is one name/value pair of an object.
type Member struct {
	Key string
	Val Value
}

// Kind is a JSON value type.
type Kind int

// JSON value kinds.
const (
	KindNull Kind = iota
	KindBool
	KindNumber
	KindString
	KindArray
	KindObject
)

// Get returns the member named key of an object.
func (v Value) Get(key string) (Value, bool) {
	for _, m := range v.Members {
		if m.Key == key {
			return m.Val, true
		}
	}
	return Value{}, false
}

// ErrDuplicateKey is returned when an object names a member twice.
var ErrDuplicateKey = errors.New("duplicate object key")

const maxDepth = 64

// Parse decodes one JSON text strictly (RFC 8259): UTF-8 only, no trailing
// data, no lone surrogates, and duplicate member names rejected rather than
// resolved first-wins or last-wins.
func Parse(data []byte) (Value, error) {
	if !utf8.Valid(data) {
		return Value{}, errors.New("input is not valid UTF-8")
	}
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		return Value{}, errors.New("byte-order mark not allowed")
	}
	p := &parser{s: data}
	p.ws()
	v, err := p.value(0)
	if err != nil {
		return Value{}, err
	}
	p.ws()
	if p.i != len(p.s) {
		return Value{}, p.errf("trailing data")
	}
	return v, nil
}

type parser struct {
	s []byte
	i int
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("json offset %d: %s", p.i, fmt.Sprintf(format, a...))
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\n', '\r':
			p.i++
		default:
			return
		}
	}
}

func (p *parser) lit(word string) bool {
	if strings.HasPrefix(string(p.s[p.i:]), word) {
		p.i += len(word)
		return true
	}
	return false
}

func (p *parser) value(depth int) (Value, error) {
	if depth > maxDepth {
		return Value{}, p.errf("nesting deeper than %d", maxDepth)
	}
	if p.i >= len(p.s) {
		return Value{}, p.errf("unexpected end of input")
	}
	switch c := p.s[p.i]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		s, err := p.str()
		return Value{Kind: KindString, Str: s}, err
	case c == 't' && p.lit("true"):
		return Value{Kind: KindBool, Bool: true}, nil
	case c == 'f' && p.lit("false"):
		return Value{Kind: KindBool}, nil
	case c == 'n' && p.lit("null"):
		return Value{Kind: KindNull}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	}
	return Value{}, p.errf("unexpected character %q", p.s[p.i])
}

func (p *parser) object(depth int) (Value, error) {
	p.i++ // {
	v := Value{Kind: KindObject}
	seen := map[string]bool{}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == '}' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != '"' {
			return Value{}, p.errf("expected member name")
		}
		k, err := p.str()
		if err != nil {
			return Value{}, err
		}
		if seen[k] {
			return Value{}, fmt.Errorf("%w %q", ErrDuplicateKey, k)
		}
		seen[k] = true
		p.ws()
		if p.i >= len(p.s) || p.s[p.i] != ':' {
			return Value{}, p.errf("expected ':'")
		}
		p.i++
		p.ws()
		m, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		v.Members = append(v.Members, Member{k, m})
		p.ws()
		if p.i >= len(p.s) {
			return Value{}, p.errf("unterminated object")
		}
		if p.s[p.i] == '}' {
			p.i++
			return v, nil
		}
		if p.s[p.i] != ',' {
			return Value{}, p.errf("expected ',' or '}'")
		}
		p.i++
	}
}

func (p *parser) array(depth int) (Value, error) {
	p.i++ // [
	v := Value{Kind: KindArray}
	p.ws()
	if p.i < len(p.s) && p.s[p.i] == ']' {
		p.i++
		return v, nil
	}
	for {
		p.ws()
		item, err := p.value(depth + 1)
		if err != nil {
			return Value{}, err
		}
		v.Items = append(v.Items, item)
		p.ws()
		if p.i >= len(p.s) {
			return Value{}, p.errf("unterminated array")
		}
		if p.s[p.i] == ']' {
			p.i++
			return v, nil
		}
		if p.s[p.i] != ',' {
			return Value{}, p.errf("expected ',' or ']'")
		}
		p.i++
	}
}

func (p *parser) number() (Value, error) {
	start := p.i
	if p.s[p.i] == '-' {
		p.i++
	}
	digits := func() int {
		n := 0
		for p.i < len(p.s) && p.s[p.i] >= '0' && p.s[p.i] <= '9' {
			p.i++
			n++
		}
		return n
	}
	if p.i < len(p.s) && p.s[p.i] == '0' {
		p.i++
	} else if digits() == 0 {
		return Value{}, p.errf("malformed number")
	}
	if p.i < len(p.s) && p.s[p.i] == '.' {
		p.i++
		if digits() == 0 {
			return Value{}, p.errf("malformed number")
		}
	}
	if p.i < len(p.s) && (p.s[p.i] == 'e' || p.s[p.i] == 'E') {
		p.i++
		if p.i < len(p.s) && (p.s[p.i] == '+' || p.s[p.i] == '-') {
			p.i++
		}
		if digits() == 0 {
			return Value{}, p.errf("malformed number")
		}
	}
	lit := string(p.s[start:p.i])
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil || math.IsInf(f, 0) {
		return Value{}, p.errf("number %s out of range", lit)
	}
	return Value{Kind: KindNumber, Num: lit}, nil
}

func (p *parser) str() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for {
		if p.i >= len(p.s) {
			return "", p.errf("unterminated string")
		}
		c := p.s[p.i]
		switch {
		case c == '"':
			p.i++
			return b.String(), nil
		case c < 0x20:
			return "", p.errf("unescaped control character in string")
		case c != '\\':
			b.WriteByte(c)
			p.i++
			continue
		}
		p.i++ // backslash
		if p.i >= len(p.s) {
			return "", p.errf("unterminated escape")
		}
		e := p.s[p.i]
		p.i++
		switch e {
		case '"', '\\', '/':
			b.WriteByte(e)
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'u':
			r, err := p.hex4()
			if err != nil {
				return "", err
			}
			if utf16.IsSurrogate(r) {
				if r >= 0xDC00 || !p.lit(`\u`) {
					return "", p.errf("lone surrogate in string")
				}
				r2, err := p.hex4()
				if err != nil {
					return "", err
				}
				if r2 < 0xDC00 || r2 > 0xDFFF {
					return "", p.errf("lone surrogate in string")
				}
				r = utf16.DecodeRune(r, r2)
			}
			b.WriteRune(r)
		default:
			return "", p.errf("invalid escape \\%c", e)
		}
	}
}

func (p *parser) hex4() (rune, error) {
	if p.i+4 > len(p.s) {
		return 0, p.errf("short \\u escape")
	}
	n, err := strconv.ParseUint(string(p.s[p.i:p.i+4]), 16, 16)
	if err != nil {
		return 0, p.errf("bad \\u escape")
	}
	p.i += 4
	return rune(n), nil
}

// Canonical returns the RFC 8785 (JCS) serialization of v.
func Canonical(v Value) ([]byte, error) {
	var b strings.Builder
	if err := writeJCS(&b, v); err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}

func writeJCS(b *strings.Builder, v Value) error {
	switch v.Kind {
	case KindNull:
		b.WriteString("null")
	case KindBool:
		b.WriteString(strconv.FormatBool(v.Bool))
	case KindNumber:
		f, err := strconv.ParseFloat(v.Num, 64)
		if err != nil {
			return err
		}
		b.WriteString(esNumber(f))
	case KindString:
		writeJCSString(b, v.Str)
	case KindArray:
		b.WriteByte('[')
		for i, it := range v.Items {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeJCS(b, it); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case KindObject:
		ms := append([]Member(nil), v.Members...)
		sort.Slice(ms, func(i, j int) bool { return utf16Less(ms[i].Key, ms[j].Key) })
		b.WriteByte('{')
		for i, m := range ms {
			if i > 0 {
				b.WriteByte(',')
			}
			writeJCSString(b, m.Key)
			b.WriteByte(':')
			if err := writeJCS(b, m.Val); err != nil {
				return err
			}
		}
		b.WriteByte('}')
	}
	return nil
}

// utf16Less orders keys by UTF-16 code units (RFC 8785 §3.2.3).
func utf16Less(a, b string) bool {
	ua, ub := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

// writeJCSString escapes per RFC 8785 §3.2.2.2: only '"', '\\' and C0
// controls, short forms where they exist, \u00xx (lowercase) otherwise.
func writeJCSString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// esNumber formats f as ECMAScript Number::toString does (ECMA-262
// §6.1.6.1.20), which RFC 8785 §3.2.2.3 requires.
func esNumber(f float64) string {
	if f == 0 {
		return "0" // also -0
	}
	neg := f < 0
	if neg {
		f = -f
	}
	// Shortest round-trip digits and the decimal exponent.
	e := strconv.FormatFloat(f, 'e', -1, 64) // d.ddddde±XX
	mant, expStr, _ := strings.Cut(e, "e")
	digits := strings.Replace(mant, ".", "", 1)
	x, _ := strconv.Atoi(expStr)
	k, n := len(digits), x+1 // value = 0.digits × 10^n
	var out string
	switch {
	case k <= n && n <= 21:
		out = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		out = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		out = "0." + strings.Repeat("0", -n) + digits
	default:
		sign := "+"
		if n-1 < 0 {
			sign = "-"
		}
		exp := n - 1
		if exp < 0 {
			exp = -exp
		}
		out = digits[:1]
		if k > 1 {
			out += "." + digits[1:]
		}
		out += "e" + sign + strconv.Itoa(exp)
	}
	if neg {
		return "-" + out
	}
	return out
}
