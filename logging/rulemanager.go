package logging

import (
	"path/filepath"
	"strings"
)

type RuleManager struct {
	Rules map[string]Level
}

func (rm *RuleManager) AddRule(rule string, level Level) {

	if rm.Rules == nil {
		rm.Rules = make(map[string]Level)
	}

	r := strings.TrimRight(rule, "/")
	rm.Rules[r] = level
}

func (rm *RuleManager) ShouldLog(file string, level Level) bool {

	// apply the first matching rule
	for r, l := range rm.Rules {
		if filepath.Dir(file) == r {
			if level <= l {
				return true
			} else {
				return false
			}
		}
	}

	// if there is no matching rule for the package, log normally
	return true
}
