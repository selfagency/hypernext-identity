package solid

import (
	"strings"
	"testing"
)

// TestApplyNPatchInsertDelete proves a combined INSERT DATA + DELETE DATA
// patch mutates the current document.
func TestApplyNPatchInsertDelete(t *testing.T) {
	current := `@prefix ex: <http://example.com/>.
ex:s ex:p "old".`
	patch := `INSERT DATA { ex:s ex:q "new". } DELETE DATA { ex:s ex:p "old". }`
	got, err := applyNPatch(current, patch)
	if err != nil {
		t.Fatalf("applyNPatch: %v", err)
	}
	if !strings.Contains(got, `http://example.com/s <http://example.com/q> "new".`) {
		t.Fatalf("missing inserted triple:\n%s", got)
	}
	if strings.Contains(got, `"old"`) {
		t.Fatalf("deleted triple still present:\n%s", got)
	}
}

// TestApplyNPatchParseCurrentError proves a malformed current document
// surfaces an error.
func TestApplyNPatchParseCurrentError(t *testing.T) {
	if _, err := applyNPatch("not valid turtle", "INSERT DATA { <http://e.com/s> <http://e.com/p> \"v\". }"); err == nil {
		t.Fatal("expected error for malformed current document")
	}
}

// TestApplyNPatchUnsupportedOperation proves non-INSERT/DELETE patches error.
func TestApplyNPatchUnsupportedOperation(t *testing.T) {
	if _, err := applyNPatch("", "DELETE WHERE { ?s ?p ?o }"); err == nil {
		t.Fatal("expected error for unsupported patch operation")
	}
}

// TestApplyNPatchMalformedTriple proves a triple with too few terms errors.
func TestApplyNPatchMalformedTriple(t *testing.T) {
	if _, err := applyNPatch("", "INSERT DATA { <http://e.com/s> <http://e.com/p> }"); err == nil {
		t.Fatal("expected error for malformed triple")
	}
}

// TestApplyNPatchUnknownPrefix proves an unknown prefixed name errors.
func TestApplyNPatchUnknownPrefix(t *testing.T) {
	if _, err := applyNPatch("", "INSERT DATA { ex:s ex:p \"v\". }"); err == nil {
		t.Fatal("expected error for unknown prefix")
	}
}

// TestApplyNPatchMalformedIRI proves a malformed IRI errors.
func TestApplyNPatchMalformedIRI(t *testing.T) {
	if _, err := applyNPatch("", "INSERT DATA { <http://e.com/s> <http://e.com/p> <unclosed. }"); err == nil {
		t.Fatal("expected error for malformed IRI")
	}
}

// TestApplyNPatchUnsupportedTerm proves a bare (non-IRI, non-literal) term
// errors.
func TestApplyNPatchUnsupportedTerm(t *testing.T) {
	if _, err := applyNPatch("", "INSERT DATA { <http://e.com/s> <http://e.com/p> bare. }"); err == nil {
		t.Fatal("expected error for unsupported term")
	}
}

// TestApplyNPatchEmptyRelativeIRI proves the empty relative IRI (current
// document base) is accepted and serialized back as <>.
func TestApplyNPatchEmptyRelativeIRI(t *testing.T) {
	got, err := applyNPatch("", `INSERT DATA { <> <http://e.com/p> "v". }`)
	if err != nil {
		t.Fatalf("applyNPatch: %v", err)
	}
	if !strings.Contains(got, `<> <http://e.com/p> "v".`) {
		t.Fatalf("missing empty-relative-IRI triple:\n%s", got)
	}
}

// TestApplyNPatchLiteralWithDot proves a literal containing a dot is not
// split into a new statement.
func TestApplyNPatchLiteralWithDot(t *testing.T) {
	got, err := applyNPatch("", `INSERT DATA { <http://e.com/s> <http://e.com/p> "a.b". }`)
	if err != nil {
		t.Fatalf("applyNPatch: %v", err)
	}
	if !strings.Contains(got, `"a.b"`) {
		t.Fatalf("literal with dot mangled:\n%s", got)
	}
}

// TestApplyNPatchPrefixDeclaration proves @prefix lines are preserved and
// prefixed names expand correctly.
func TestApplyNPatchPrefixDeclaration(t *testing.T) {
	current := `@prefix ex: <http://example.com/>.
ex:s ex:p "v".`
	got, err := applyNPatch(current, `INSERT DATA { ex:s ex:q "w". }`)
	if err != nil {
		t.Fatalf("applyNPatch: %v", err)
	}
	if !strings.Contains(got, "@prefix ex: <http://example.com/>.") {
		t.Fatalf("prefix declaration lost:\n%s", got)
	}
	if !strings.Contains(got, `http://example.com/s <http://example.com/q> "w".`) {
		t.Fatalf("prefixed name not expanded:\n%s", got)
	}
}

// TestApplyNPatchAKeyword proves the `a` keyword expands to rdf:type.
func TestApplyNPatchAKeyword(t *testing.T) {
	got, err := applyNPatch("", `INSERT DATA { <http://e.com/s> a <http://e.com/Type>. }`)
	if err != nil {
		t.Fatalf("applyNPatch: %v", err)
	}
	if !strings.Contains(got, "http://www.w3.org/1999/02/22-rdf-syntax-ns#type") {
		t.Fatalf("a keyword not expanded:\n%s", got)
	}
}

// TestApplyNPatchMalformedPrefixedName proves a prefixed name with no local
// part errors.
func TestApplyNPatchMalformedPrefixedName(t *testing.T) {
	if _, err := applyNPatch("", `INSERT DATA { <http://e.com/s> <http://e.com/p> ex:. }`); err == nil {
		t.Fatal("expected error for malformed prefixed name")
	}
}
