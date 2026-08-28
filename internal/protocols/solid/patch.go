package solid

import (
	"fmt"
	"sort"
	"strings"
)

// triple is a single RDF statement with expanded IRIs.
type triple struct {
	subject   string
	predicate string
	object    string
}

// applyNPatch applies a SPARQL-update INSERT DATA / DELETE DATA patch to a
// Turtle document. It supports the pragmatic subset used by real Solid PATCH
// clients: INSERT DATA { ... } and DELETE DATA { ... } blocks of triples with
// full IRIs, prefixed names, the `a` keyword, and string literals. WHERE
// clauses, graph patterns, FILTER, and blank nodes are out of scope.
func applyNPatch(current, patch string) (string, error) {
	prefixes, curTriples, err := parseTurtle(current)
	if err != nil {
		return "", fmt.Errorf("parse current: %w", err)
	}

	insert, del, err := parsePatch(patch, prefixes)
	if err != nil {
		return "", err
	}

	set := map[triple]bool{}
	for _, t := range curTriples {
		set[t] = true
	}
	for _, t := range del {
		delete(set, t)
	}
	for _, t := range insert {
		set[t] = true
	}

	return serializeTurtle(prefixes, set), nil
}

// parsePatch extracts INSERT DATA and DELETE DATA triple sets from a
// SPARQL-update body.
func parsePatch(patch string, prefixes map[string]string) (insert, del []triple, err error) {
	// Normalize: strip the outer braces and split on INSERT/DELETE DATA.
	body := strings.TrimSpace(patch)
	// Find INSERT DATA { ... } and DELETE DATA { ... } blocks.
	for {
		body = strings.TrimSpace(body)
		if body == "" {
			break
		}
		var block string
		var isInsert bool
		switch {
		case strings.HasPrefix(body, "INSERT DATA"):
			isInsert = true
			rest := strings.TrimSpace(strings.TrimPrefix(body, "INSERT DATA"))
			block, body = extractBraced(rest)
		case strings.HasPrefix(body, "DELETE DATA"):
			isInsert = false
			rest := strings.TrimSpace(strings.TrimPrefix(body, "DELETE DATA"))
			block, body = extractBraced(rest)
		default:
			return nil, nil, fmt.Errorf("unsupported patch operation (only INSERT DATA / DELETE DATA)")
		}
		ts, err := parseTriples(block, prefixes)
		if err != nil {
			return nil, nil, err
		}
		if isInsert {
			insert = append(insert, ts...)
		} else {
			del = append(del, ts...)
		}
	}
	return insert, del, nil
}

// extractBraced returns the content inside the first {...} and the remainder.
func extractBraced(s string) (content, rest string) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") {
		return "", s
	}
	depth := 0
	for i, r := range s {
		switch r {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return s[1:i], strings.TrimSpace(s[i+1:])
			}
		}
	}
	return "", ""
}

// parseTurtle parses a Turtle document into prefixes and a triple set.
func parseTurtle(doc string) (map[string]string, []triple, error) {
	prefixes := map[string]string{}
	// Collect @prefix declarations.
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "@prefix") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "@prefix"))
			// p: <iri>.
			colon := strings.Index(rest, ":")
			if colon < 0 {
				continue
			}
			name := strings.TrimSpace(rest[:colon])
			iri := extractIRI(rest[colon+1:])
			if iri != "" {
				prefixes[name] = iri
			}
		}
	}
	ts, err := parseTriples(doc, prefixes)
	return prefixes, ts, err
}

// parseTriples parses a block of Turtle statements into triples.
func parseTriples(block string, prefixes map[string]string) ([]triple, error) {
	var out []triple
	// Split on '.' at statement boundaries (naive but fine for the subset).
	statements := splitStatements(block)
	for _, st := range statements {
		st = strings.TrimSpace(st)
		if st == "" || strings.HasPrefix(st, "@prefix") {
			continue
		}
		// Split into subject predicate object.
		parts := splitTerms(st)
		if len(parts) < 3 {
			return nil, fmt.Errorf("malformed triple: %q", st)
		}
		subj, err := expandTerm(parts[0], prefixes)
		if err != nil {
			return nil, err
		}
		pred, err := expandTerm(parts[1], prefixes)
		if err != nil {
			return nil, err
		}
		obj, err := expandTerm(parts[2], prefixes)
		if err != nil {
			return nil, err
		}
		out = append(out, triple{subject: subj, predicate: pred, object: obj})
	}
	return out, nil
}

// splitStatements splits a Turtle block on '.' terminators, ignoring dots
// inside literals and <...> IRIs.
func splitStatements(block string) []string {
	var out []string
	var cur strings.Builder
	inLiteral := false
	inIRI := false
	for _, r := range block {
		switch {
		case r == '"':
			inLiteral = !inLiteral
			cur.WriteRune(r)
		case r == '<':
			inIRI = true
			cur.WriteRune(r)
		case r == '>':
			inIRI = false
			cur.WriteRune(r)
		case r == '.' && !inLiteral && !inIRI:
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteRune(r)
		}
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, cur.String())
	}
	return out
}

// splitTerms splits a statement into whitespace-separated terms, keeping
// literals and <...> IRIs intact.
func splitTerms(st string) []string {
	var out []string
	var cur strings.Builder
	inLiteral := false
	inIRI := false
	for _, r := range st {
		switch {
		case r == '"':
			inLiteral = !inLiteral
			cur.WriteRune(r)
		case r == '<':
			inIRI = true
			cur.WriteRune(r)
		case r == '>':
			inIRI = false
			cur.WriteRune(r)
		case (r == ' ' || r == '\t' || r == '\n') && !inLiteral && !inIRI:
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// expandTerm expands a Turtle term to a full IRI or literal.
func expandTerm(term string, prefixes map[string]string) (string, error) {
	term = strings.TrimSpace(term)
	switch {
	case term == "a":
		return "http://www.w3.org/1999/02/22-rdf-syntax-ns#type", nil
	case term == "<>":
		// Empty relative IRI: the current document base.
		return "", nil
	case strings.HasPrefix(term, "<"):
		iri := extractIRI(term)
		if iri == "" {
			return "", fmt.Errorf("malformed IRI: %q", term)
		}
		return iri, nil
	case strings.HasPrefix(term, `"`):
		// Literal: strip quotes.
		return strings.Trim(term, `"`), nil
	case strings.Contains(term, ":"):
		// Prefixed name p:local.
		colon := strings.Index(term, ":")
		if colon <= 0 || colon >= len(term)-1 {
			return "", fmt.Errorf("malformed prefixed name: %q", term)
		}
		prefix := term[:colon]
		local := term[colon+1:]
		base, ok := prefixes[prefix]
		if !ok {
			return "", fmt.Errorf("unknown prefix %q", prefix)
		}
		return base + local, nil
	default:
		return "", fmt.Errorf("unsupported term: %q", term)
	}
}

// extractIRI returns the IRI inside <...>.
func extractIRI(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "<") {
		return ""
	}
	end := strings.Index(s, ">")
	if end < 0 {
		return ""
	}
	return s[1:end]
}

// serializeTurtle renders a triple set back to Turtle.
func serializeTurtle(prefixes map[string]string, set map[triple]bool) string {
	var b strings.Builder
	// Emit prefixes in sorted order.
	names := make([]string, 0, len(prefixes))
	for name := range prefixes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Fprintf(&b, "@prefix %s: <%s>.\n", name, prefixes[name])
	}
	if len(names) > 0 {
		b.WriteString("\n")
	}
	ts := make([]triple, 0, len(set))
	for t := range set {
		ts = append(ts, t)
	}
	sort.Slice(ts, func(i, j int) bool {
		if ts[i].subject != ts[j].subject {
			return ts[i].subject < ts[j].subject
		}
		if ts[i].predicate != ts[j].predicate {
			return ts[i].predicate < ts[j].predicate
		}
		return ts[i].object < ts[j].object
	})
	for _, t := range ts {
		subj := t.subject
		if subj == "" {
			subj = "<>"
		}
		fmt.Fprintf(&b, "%s <%s> \"%s\".\n", subj, t.predicate, t.object)
	}
	return b.String()
}
