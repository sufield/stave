package sirfacts

import (
	"bytes"
	"testing"
)

// smtStructurallyBalanced reports whether s is a structurally well-formed
// sequence of SMT-LIB S-expressions: parentheses balance once string literals
// ("..." with "" as an escaped quote), quoted symbols (|...|), and line
// comments (; to end of line) are accounted for. It is a deliberately small
// lexer — enough to detect an attacker-controlled identifier that breaks out
// of its quoting and injects extra/un-balanced parens into the solver input.
func smtStructurallyBalanced(s string) bool {
	depth := 0
	for i := 0; i < len(s); {
		switch s[i] {
		case ';': // line comment runs to end of line
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case '"': // string literal; "" is an escaped quote
			i++
			for i < len(s) {
				if s[i] == '"' {
					if i+1 < len(s) && s[i+1] == '"' {
						i += 2
						continue
					}
					i++
					break
				}
				i++
			}
		case '|': // quoted symbol runs to the next unescaped |
			i++
			for i < len(s) && s[i] != '|' {
				i++
			}
			if i >= len(s) {
				return false // unterminated quoted symbol
			}
			i++ // consume closing |
		case '(':
			depth++
			i++
		case ')':
			depth--
			if depth < 0 {
				return false
			}
			i++
		default:
			i++
		}
	}
	return depth == 0
}

// FuzzSerializeSMT2 asserts the SMT-LIB emission injection-safety invariant: for
// any fact (subject, predicate, object), SerializeSMT2 must either return an
// error OR emit structurally well-formed SMT-LIB. It must never silently emit
// malformed text where an attacker-controlled identifier has broken out of its
// quoting.
//
// Why a violation matters: the smt2 export is consumed by external reasoning
// engines (Z3, cvc5). An asset id, property value, or property-key-derived
// predicate that injects an unbalanced paren or a stray token corrupts the
// solver input — at best a parse error, at worst a silently different model,
// so the facts handed to the prover no longer describe the real account.
// Subject/object are escaped as SMT string literals (smt2Quote); a predicate
// that cannot be rendered as a valid SMT-LIB symbol (one containing '|' or
// '\') is rejected up front rather than emitted as malformed |...| text.
func FuzzSerializeSMT2(f *testing.F) {
	type seed struct{ subj, pred, obj string }
	seeds := []seed{
		{"arn:aws:s3:::bucket", "has_public_access", "true"},
		{`a") (assert false) (`, "has_action", "x"},    // paren/quote injection via subject
		{"s", "iam:PassedToService", `o") (check-sat`}, // colon predicate (-> |...|) + object injection
		{"s\nx", "has_action", "o ; not a comment"},    // newline + semicolon inside string args
		{`"`, "has_action", `""`},                      // bare/double quotes
		{`back\slash`, "has_action", `more\\`},         // backslashes in string args (safe in SMT strings)
		{"|x|", "has_action", "|y|"},                   // pipes in string args (safe — inside "...")
		{"s", `evil|sym`, "o"},                         // pipe in predicate -> must error, not emit |evil|sym|
		{"s", `back\sym`, "o"},                         // backslash in predicate -> must error
		{"s", "", "o"},                                 // empty predicate
	}
	for _, s := range seeds {
		f.Add(s.subj, s.pred, s.obj)
	}

	f.Fuzz(func(t *testing.T, subj, pred, obj string) {
		for _, closed := range []bool{false, true} {
			var buf bytes.Buffer
			err := SerializeSMT2([]Fact{{Subject: subj, Predicate: pred, Object: obj}}, &buf, SMT2Options{ClosedWorld: closed})
			if err != nil {
				// Refusing an un-representable identifier is the fail-loud contract.
				continue
			}
			if !smtStructurallyBalanced(buf.String()) {
				t.Fatalf("SerializeSMT2 (closedWorld=%v) emitted structurally malformed SMT-LIB for subj=%q pred=%q obj=%q:\n%s",
					closed, subj, pred, obj, buf.String())
			}
		}
	})
}
