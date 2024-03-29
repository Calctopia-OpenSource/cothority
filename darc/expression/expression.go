/*
Package expression contains the definition and implementation of a simple
language for defining complex policies. We define the language in extended-BNF notation,
the syntax we use is from: https://en.wikipedia.org/wiki/Extended_Backus%E2%80%93Naur_form

	expr = term, [ '&', term ]*
	term = factor, [ '|', factor ]*
	factor = '(', expr, ')' | id | openid
	identity = (darc|ed25519|x509ec):[0-9a-fA-F]+
	proxy = proxy:[0-9a-fA-F]+:[^ \n\t]*
	evm_identity = evm_contract:[0-9a-fA-F]+:0x[0-9a-fA-F]+
	attr = attr:[0-9a-zA-Z\-\_]+:[^ \n\t]*
	threshold = threshold<\d+/\d+ [',' id]* >

Examples:

	ed25519:deadbeef // every id evaluates to a boolean
	(ed25519:a & x509ec:b) | (darc:c & ed25519:d)
	proxy:deadbeef:me@example.com // where deadbeef is a ed25519 public key
	attr:time_interval:before=5pm&after=9am & ed25519:deadbeef

In the simplest case, the evaluation of an expression is performed against a
set of valid ids.  Suppose we have the expression (a:a & b:b) | (c:c & d:d),
and the set of valid ids is [a:a, b:b], then the expression will evaluate to
true.  If the set of valid ids is [a:a, c:c], then the expression will evaluate
to false. However, the user is able to provide a ValueCheckFn to customise how
the expressions are evaluated.

EXTENSION - NOT YET IMPLEMENTED:
To support threshold signatures, we extend the syntax to include the following.
	thexpr = '[', id, [ ',', id ]*, ']', '/', digit
*/
package expression

import (
	"errors"
	"fmt"
	"strings"

	parsec "github.com/prataprc/goparsec"
)

var (
	errScannerNotEmpty = errors.New("parsing failed - scanner is not empty")
	errFailedToCast    = errors.New("evauluation failed - result is not bool")
)

// ValueCheckFn is a function that will be called when the parser is
// parsing/evaluating an expression.
type ValueCheckFn func(string) bool

// Expr represents the unprocessed expression of our DSL.
type Expr []byte

// InitParser creates the root parser
func InitParser(fn ValueCheckFn) parsec.Parser {
	// Y is root Parser, usually called as `s` in CFG theory.
	var Y parsec.Parser
	var sum, value parsec.Parser // circular rats

	// Terminal rats
	var openparan = parsec.Token(`\(`, "OPENPARAN")
	var closeparan = parsec.Token(`\)`, "CLOSEPARAN")
	var andop = parsec.Token(`&`, "AND")
	var orop = parsec.Token(`\|`, "OR")

	// Threshold expression.
	tElems := parsec.OrdChoice(one2one, identity(), proxy(), evmIdentity())
	startT := parsec.Token("threshold<", "STARTT")
	endT := parsec.Token(">", "ENDT")
	tVal := parsec.Token(`\d+/\d+`, "TVAL")
	tSep := parsec.Token(`,`, "TSEP")

	threshold := parsec.And(exprThresholeNode(fn),
		startT,
		parsec.Kleene(one2one, tVal, tSep),
		parsec.Kleene(nil, tElems, tSep), endT)

	// NonTerminal rats
	// sumOp -> "&" |  "|"
	var sumOp = parsec.OrdChoice(one2one, andop, orop)

	// value -> "(" expr ")"
	var groupExpr = parsec.And(exprNode, openparan, &sum, closeparan)

	// (andop prod)*
	var prodK = parsec.Kleene(nil, parsec.And(many2many, sumOp, &value), nil)

	// Circular rats come to life
	// sum -> prod (andop prod)*
	sum = parsec.And(sumNode(fn), &value, prodK)
	// value -> id | "(" expr ")"
	value = parsec.OrdChoice(exprValueNode(fn), identity(), proxy(),
		evmIdentity(), attr(), threshold, groupExpr)
	// expr  -> sum
	Y = parsec.OrdChoice(one2one, sum)
	return Y
}

// Evaluate uses the input parser to evaluate the expression expr. It returns
// the result of the evaluate (a boolean), but the result is only valid if
// there are no errors.
func Evaluate(parser parsec.Parser, expr Expr) (bool, error) {
	v, s := parser(parsec.NewScanner(expr))
	_, s = s.SkipWS()
	if !s.Endof() {
		rest, _ := s.Match(".*")
		return false, fmt.Errorf("%v: (rest = %v)", errScannerNotEmpty, string(rest))
	}
	vv, ok := v.(bool)
	if !ok {
		return false, errFailedToCast
	}
	return vv, nil
}

// DefaultParser creates a parser and evaluates the expression expr, every id
// in pks will evaluate to true.
func DefaultParser(expr Expr, ids ...string) (bool, error) {
	return Evaluate(InitParser(func(s string) bool {
		for _, k := range ids {
			if k == s {
				return true
			}
		}
		return false
	}), expr)
}

// InitAndExpr creates an expression where & (and) is used to combine all the
// IDs.
func InitAndExpr(ids ...string) Expr {
	return Expr(strings.Join(ids, " & "))
}

// InitOrExpr creates an expression where | (or) is used to combine all the
// IDs.
func InitOrExpr(ids ...string) Expr {
	return Expr(strings.Join(ids, " | "))
}

// AddOrElement adds a single identity and ORs it with the previous expression.
func (e Expr) AddOrElement(id string) Expr {
	return Expr(fmt.Sprintf("%s | %s", e, id))
}

// AddAndElement adds a single identity and ANDs it with the previous
// expression.
func (e Expr) AddAndElement(id string) Expr {
	return Expr(fmt.Sprintf("%s & %s", e, id))
}

// Accepts tokens of the form "identity_type:HEX"
func identity() parsec.Parser {
	return func(s parsec.Scanner) (parsec.ParsecNode, parsec.Scanner) {
		_, s = s.SkipAny(`^[ \n\t]+`)
		p := parsec.Token(`(darc|ed25519|x509ec):[0-9a-fA-F]+`, "HEX")
		return p(s)
	}
}

// Accepts tokens of the form "proxy:edd25519-pubkey:associate_data"
func proxy() parsec.Parser {
	return func(s parsec.Scanner) (parsec.ParsecNode, parsec.Scanner) {
		_, s = s.SkipAny(`^[ \n\t]+`)
		p := parsec.Token(`proxy:[0-9a-fA-F]+:[^ \n\t]*`, "PROXY")
		return p(s)
	}
}

func evmIdentity() parsec.Parser {
	return func(s parsec.Scanner) (parsec.ParsecNode, parsec.Scanner) {
		_, s = s.SkipAny(`^[ \n\t]+`)
		p := parsec.Token(`evm_contract:[0-9a-fA-F]+:0x[0-9a-fA-F]+`, "EVM")
		return p(s)
	}
}

// Accepts tokens of the form that begins with "attr:"
func attr() parsec.Parser {
	return func(s parsec.Scanner) (parsec.ParsecNode, parsec.Scanner) {
		_, s = s.SkipAny(`^[ \n\t]+`)
		p := parsec.Token(`attr:[0-9a-zA-Z\-\_]+:[^ \n\t]*`, "ATTR")
		return p(s)
	}
}

func sumNode(fn ValueCheckFn) func(ns []parsec.ParsecNode) parsec.ParsecNode {
	return func(ns []parsec.ParsecNode) parsec.ParsecNode {
		if len(ns) > 0 {
			val := ns[0].(bool)
			for _, x := range ns[1].([]parsec.ParsecNode) {
				y := x.([]parsec.ParsecNode)
				n := y[1].(bool)
				switch y[0].(*parsec.Terminal).Name {
				case "AND":
					val = val && n
				case "OR":
					val = val || n
				}
			}
			return val
		}
		return nil
	}
}

func exprValueNode(fn ValueCheckFn) func(ns []parsec.ParsecNode) parsec.ParsecNode {
	return func(ns []parsec.ParsecNode) parsec.ParsecNode {
		if len(ns) == 0 {
			return nil
		} else if term, ok := ns[0].(*parsec.Terminal); ok {
			return fn(term.Value)
		}
		return ns[0]
	}
}

// exprThresholeNode groups the matching elements of the threshold expression
// and sends it to the callback function. We are expecting ns to contain 4
// elements: the opening tag 'threshold<', the threshold '1/2', the list of ids
// [darc:aa, ...], and the closing tag '>'.
func exprThresholeNode(fn ValueCheckFn) func(ns []parsec.ParsecNode) parsec.ParsecNode {
	return func(ns []parsec.ParsecNode) parsec.ParsecNode {
		// the threshold '1/2'
		elems := []string{ns[1].(*parsec.Terminal).Value}

		// the list of ids
		nodes := ns[2].([]parsec.ParsecNode)
		for _, n := range nodes {
			elems = append(elems, n.(*parsec.Terminal).Value)
		}

		res := ns[0].(*parsec.Terminal).Value + strings.Join(elems, ",") +
			ns[3].(*parsec.Terminal).Value
		return fn(res)
	}
}

func exprNode(ns []parsec.ParsecNode) parsec.ParsecNode {
	if len(ns) == 0 {
		return nil
	}
	return ns[1]
}

func one2one(ns []parsec.ParsecNode) parsec.ParsecNode {
	if ns == nil || len(ns) == 0 {
		return nil
	}
	return ns[0]
}

func many2many(ns []parsec.ParsecNode) parsec.ParsecNode {
	if ns == nil || len(ns) == 0 {
		return nil
	}
	return ns
}
