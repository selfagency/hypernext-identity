package solid

import (
	"context"
	"io"
	"strings"

	"github.com/selfagency/sovereign/internal/storage"
)

// WACChecker evaluates Web Access Control .acl rule documents, falling back
// to an ownership-based checker when no ACL resource exists. It implements
// solid.ACLChecker.
type WACChecker struct {
	// Backend returns the storage backend for a tenant.
	Backend func(tenantID string) storage.Backend
	// Owner is the fallback ownership-based checker used when no .acl exists.
	Owner ACLChecker
}

// CanRead reports whether agent may read resource per WAC (or ownership
// fallback).
func (w *WACChecker) CanRead(ctx context.Context, resource string, agent Agent) bool {
	return w.allowed(ctx, resource, agent, "Read")
}

// CanWrite reports whether agent may write resource per WAC (or ownership
// fallback).
func (w *WACChecker) CanWrite(ctx context.Context, resource string, agent Agent) bool {
	return w.allowed(ctx, resource, agent, "Write")
}

// allowed evaluates the .acl for resource, falling back to the ownership
// checker when no ACL resource exists.
func (w *WACChecker) allowed(ctx context.Context, resource string, agent Agent, mode string) bool {
	aclKey := aclResourceFor(resource)
	be := w.Backend("")
	rc, _, err := be.Get(ctx, aclKey)
	if err != nil {
		// No ACL resource -> ownership fallback.
		if mode == "Read" {
			return w.Owner.CanRead(ctx, resource, agent)
		}
		return w.Owner.CanWrite(ctx, resource, agent)
	}
	defer func() { _ = rc.Close() }()
	rules, err := io.ReadAll(rc)
	if err != nil {
		return false
	}
	return wacPermits(string(rules), resource, agent.WebID, mode)
}

// aclResourceFor returns the ACL resource key for a resource. Per Solid, the
// ACL for a resource is a sibling <resource>.acl.
func aclResourceFor(resource string) string {
	return resource + ".acl"
}

// wacPermits parses an ACL Turtle document and reports whether agent is
// granted mode on resource. It supports acl:agent, acl:agentClass
// (acl:AuthenticatedAgent), acl:accessTo, and acl:mode.
func wacPermits(aclDoc, resource, agentWebID, mode string) bool {
	// Normalize the mode to the acl: namespace.
	modeIRI := "http://www.w3.org/ns/auth/acl#" + mode
	// Parse the ACL into rules.
	rules := parseACLRules(aclDoc)
	for _, rule := range rules {
		if !rule.accessTo(resource) {
			continue
		}
		if !rule.grantsMode(modeIRI) {
			continue
		}
		if rule.allowsAgent(agentWebID) {
			return true
		}
	}
	return false
}

// aclRule is a single acl:Authorization.
type aclRule struct {
	agents     []string // acl:agent WebIDs
	agentClass []string // acl:agentClass (e.g. acl:AuthenticatedAgent)
	targets    []string // acl:accessTo resources
	modes      []string // acl:mode IRIs
}

// accessTo reports whether the rule applies to resource.
func (r *aclRule) accessTo(resource string) bool {
	for _, a := range r.targets {
		// Match the resource or a relative reference to it.
		if a == resource || strings.HasSuffix(a, resource) || strings.HasSuffix(resource, a) {
			return true
		}
	}
	return false
}

// grantsMode reports whether the rule grants modeIRI.
func (r *aclRule) grantsMode(modeIRI string) bool {
	for _, m := range r.modes {
		if m == modeIRI {
			return true
		}
	}
	return false
}

// allowsAgent reports whether the rule grants access to agentWebID.
func (r *aclRule) allowsAgent(agentWebID string) bool {
	for _, a := range r.agents {
		if a == agentWebID {
			return true
		}
	}
	for _, c := range r.agentClass {
		// acl:AuthenticatedAgent matches any non-empty WebID.
		if c == "http://www.w3.org/ns/auth/acl#AuthenticatedAgent" && agentWebID != "" {
			return true
		}
	}
	return false
}

// parseACLRules parses an ACL Turtle document into acl:Authorization rules.
// It handles the Turtle statement structure: a subject followed by
// ;-separated predicate-object pairs, with ,-separated object lists.
func parseACLRules(doc string) []aclRule {
	prefixes := map[string]string{}
	for _, line := range strings.Split(doc, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "@prefix") {
			rest := strings.TrimSpace(strings.TrimPrefix(line, "@prefix"))
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

	var rules []aclRule
	for _, st := range splitStatements(doc) {
		st = strings.TrimSpace(st)
		if st == "" || strings.HasPrefix(st, "@prefix") {
			continue
		}
		rule := parseACLStatement(st, prefixes)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}
	return rules
}

// parseACLStatement parses one Turtle statement into an aclRule. A statement
// is a subject followed by ;-separated predicate-object pairs; objects may be
// ,-separated lists.
func parseACLStatement(st string, prefixes map[string]string) *aclRule {
	// Split the statement into a subject and the predicate-object tail.
	// The subject is the first term; the rest is predicate-object pairs.
	terms := splitTerms(st)
	if len(terms) < 3 {
		return nil
	}
	rule := &aclRule{}
	// Walk the remaining terms: predicate, then one or more objects.
	i := 1
	for i < len(terms) {
		pred, err := expandTerm(strings.TrimSuffix(terms[i], ";"), prefixes)
		if err != nil {
			return nil
		}
		i++
		// Collect objects until the next predicate (a term ending in ';' or
		// the next term that is a predicate). Objects may be comma-separated.
		for i < len(terms) {
			objTerm := strings.TrimSuffix(terms[i], ",")
			objTerm = strings.TrimSuffix(objTerm, ";")
			obj, err := expandTerm(objTerm, prefixes)
			if err != nil {
				return nil
			}
			addACLObject(rule, pred, obj)
			i++
			// A term ending in ';' ends this predicate's object list.
			if strings.HasSuffix(terms[i-1], ";") {
				break
			}
			// A term ending in ',' continues the object list.
			if strings.HasSuffix(terms[i-1], ",") {
				continue
			}
			// Otherwise the next term is a new predicate.
			break
		}
	}
	return rule
}

// addACLObject records a predicate-object pair on the rule.
func addACLObject(rule *aclRule, pred, obj string) {
	switch pred {
	case "http://www.w3.org/ns/auth/acl#agent":
		rule.agents = append(rule.agents, obj)
	case "http://www.w3.org/ns/auth/acl#agentClass":
		rule.agentClass = append(rule.agentClass, obj)
	case "http://www.w3.org/ns/auth/acl#accessTo":
		rule.targets = append(rule.targets, obj)
	case "http://www.w3.org/ns/auth/acl#mode":
		rule.modes = append(rule.modes, obj)
	}
}
