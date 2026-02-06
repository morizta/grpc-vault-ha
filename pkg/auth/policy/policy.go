// Package policy provides ACL policy evaluation
package policy

import (
	"errors"
	"path"
	"strings"
	"sync"
)

// Capability represents an allowed operation
type Capability string

const (
	CapabilityCreate Capability = "create"
	CapabilityRead   Capability = "read"
	CapabilityUpdate Capability = "update"
	CapabilityDelete Capability = "delete"
	CapabilityList   Capability = "list"
	CapabilitySudo   Capability = "sudo"
	CapabilityDeny   Capability = "deny"
)

var (
	ErrDenied         = errors.New("permission denied")
	ErrPolicyNotFound = errors.New("policy not found")
)

// Rule defines access rules for a path pattern
type Rule struct {
	Path         string            `json:"path"`
	Capabilities []Capability      `json:"capabilities"`
	Conditions   map[string]string `json:"conditions,omitempty"`
}

// Policy represents an ACL policy
type Policy struct {
	Name        string  `json:"name"`
	Rules       []*Rule `json:"rules"`
	Description string  `json:"description,omitempty"`
}

// Evaluator evaluates policies against requests
type Evaluator struct {
	mu       sync.RWMutex
	policies map[string]*Policy
}

// NewEvaluator creates a new policy evaluator
func NewEvaluator() *Evaluator {
	e := &Evaluator{
		policies: make(map[string]*Policy),
	}

	// Add default policy
	e.AddPolicy(&Policy{
		Name:        "default",
		Description: "Default policy with basic access",
		Rules: []*Rule{
			{
				Path:         "auth/token/lookup-self",
				Capabilities: []Capability{CapabilityRead},
			},
			{
				Path:         "auth/token/renew-self",
				Capabilities: []Capability{CapabilityUpdate},
			},
			{
				Path:         "auth/token/revoke-self",
				Capabilities: []Capability{CapabilityUpdate},
			},
		},
	})

	return e
}

// AddPolicy adds a policy to the evaluator
func (e *Evaluator) AddPolicy(policy *Policy) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies[policy.Name] = policy
	return nil
}

// GetPolicy returns a policy by name
func (e *Evaluator) GetPolicy(name string) (*Policy, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	policy, exists := e.policies[name]
	if !exists {
		return nil, ErrPolicyNotFound
	}

	return policy, nil
}

// RemovePolicy removes a policy
func (e *Evaluator) RemovePolicy(name string) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if _, exists := e.policies[name]; !exists {
		return ErrPolicyNotFound
	}

	delete(e.policies, name)
	return nil
}

// ListPolicies returns all policy names
func (e *Evaluator) ListPolicies() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()

	names := make([]string, 0, len(e.policies))
	for name := range e.policies {
		names = append(names, name)
	}
	return names
}

// EvaluationResult contains the result of policy evaluation
type EvaluationResult struct {
	Allowed      bool
	MatchedRule  string
	DenialReason string
}

// Evaluate checks if the given policies allow the requested operation
func (e *Evaluator) Evaluate(policyNames []string, resourcePath string, capability Capability, context map[string]string) *EvaluationResult {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// No policies = denied
	if len(policyNames) == 0 {
		return &EvaluationResult{
			Allowed:      false,
			DenialReason: "no policies attached",
		}
	}

	// Check each policy
	for _, policyName := range policyNames {
		policy, exists := e.policies[policyName]
		if !exists {
			continue
		}

		// Check each rule in the policy
		for _, rule := range policy.Rules {
			if !pathMatches(rule.Path, resourcePath) {
				continue
			}

			// Check for explicit deny
			if hasCapability(rule.Capabilities, CapabilityDeny) {
				return &EvaluationResult{
					Allowed:      false,
					MatchedRule:  rule.Path,
					DenialReason: "explicitly denied by policy",
				}
			}

			// Check for sudo (allows everything)
			if hasCapability(rule.Capabilities, CapabilitySudo) {
				return &EvaluationResult{
					Allowed:     true,
					MatchedRule: rule.Path,
				}
			}

			// Check for specific capability
			if hasCapability(rule.Capabilities, capability) {
				// Check conditions if present
				if len(rule.Conditions) > 0 && !checkConditions(rule.Conditions, context) {
					continue
				}

				return &EvaluationResult{
					Allowed:     true,
					MatchedRule: rule.Path,
				}
			}
		}
	}

	return &EvaluationResult{
		Allowed:      false,
		DenialReason: "no matching policy rule found",
	}
}

// Check checks if the operation is allowed (simple version)
func (e *Evaluator) Check(policyNames []string, resourcePath string, capability Capability) bool {
	result := e.Evaluate(policyNames, resourcePath, capability, nil)
	return result.Allowed
}

// pathMatches checks if a path matches a pattern
// Supports wildcards: * matches any single segment, ** matches any segments
func pathMatches(pattern, target string) bool {
	// Normalize paths
	pattern = strings.Trim(pattern, "/")
	target = strings.Trim(target, "/")

	// Handle ** (matches everything under this path)
	if strings.HasSuffix(pattern, "**") {
		prefix := strings.TrimSuffix(pattern, "**")
		prefix = strings.TrimSuffix(prefix, "/")
		return strings.HasPrefix(target, prefix)
	}

	// Handle * (matches single segment)
	if strings.Contains(pattern, "*") {
		// Split into segments
		patternParts := strings.Split(pattern, "/")
		targetParts := strings.Split(target, "/")

		if len(patternParts) != len(targetParts) {
			return false
		}

		for i, p := range patternParts {
			if p == "*" {
				continue
			}
			if p != targetParts[i] {
				return false
			}
		}
		return true
	}

	// Exact match or glob match
	if pattern == target {
		return true
	}
	matched, _ := path.Match(pattern, target)
	return matched
}

// hasCapability checks if a capability list contains the target
func hasCapability(capabilities []Capability, target Capability) bool {
	for _, c := range capabilities {
		if c == target {
			return true
		}
	}
	return false
}

// checkConditions verifies all conditions are met
func checkConditions(conditions, context map[string]string) bool {
	for key, expected := range conditions {
		if actual, exists := context[key]; !exists || actual != expected {
			return false
		}
	}
	return true
}

// ActionToCapability converts an action string to Capability
func ActionToCapability(action string) Capability {
	switch strings.ToLower(action) {
	case "create", "post":
		return CapabilityCreate
	case "read", "get":
		return CapabilityRead
	case "update", "put", "patch":
		return CapabilityUpdate
	case "delete":
		return CapabilityDelete
	case "list":
		return CapabilityList
	default:
		return Capability(action)
	}
}
