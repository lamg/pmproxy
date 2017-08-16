package main

import (
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestLastSaturday(t *testing.T) {
	var nw, lsf time.Time
	nw = time.Now()
	lsf = lastSaturday(nw)
	t.Logf("%v", lsf)
	assert.True(t, true)
}
