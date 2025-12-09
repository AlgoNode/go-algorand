package logging

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRuleManager(t *testing.T) {

	var mgr RuleManager
	mgr.AddRule("github.com/algorand/go-algorand/agreement", Info)
	mgr.AddRule("github.com/algorand/go-algorand/data/", Info)

	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/agreement/agreement.go", Panic))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/agreement/agreement.go", Error))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/agreement/agreement.go", Warn))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/agreement/agreement.go", Info))
	assert.Equal(t, false, mgr.ShouldLog("github.com/algorand/go-algorand/agreement/agreement.go", Debug))

	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/data/data.go", Panic))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/data/data.go", Error))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/data/data.go", Warn))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/data/data.go", Info))
	assert.Equal(t, false, mgr.ShouldLog("github.com/algorand/go-algorand/data/data.go", Debug))

	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/network/network.go", Panic))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/network/network.go", Error))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/network/network.go", Warn))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/network/network.go", Info))
	assert.Equal(t, true, mgr.ShouldLog("github.com/algorand/go-algorand/network/network.go", Debug))

}
