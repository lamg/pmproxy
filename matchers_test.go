package pmproxy

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestGrpMatch(t *testing.T) {
	sm, coco, loggedAddr := NewSMng("sm", nil, nil), "coco",
		"0.0.0.1"
	sm.login(coco, loggedAddr)
	gr := &GrpMtch{
		Grp: "G1",
		Um: &UsrMtch{
			Sm: sm,
		},
		Ug: map[string][]string{
			coco: {"G0", "G1"},
		},
	}
	b := gr.Match(loggedAddr)
	require.True(t, b)
}

func TestUsrMatch(t *testing.T) {
	sm, coco, loggedAddr := NewSMng("sm", nil, nil), "coco",
		"0.0.0.1"
	sm.login(coco, loggedAddr)
	um := &UsrMtch{
		Ul: []string{"pepe", "coco"},
		Sm: sm,
	}
	b := um.Match(loggedAddr)
	require.True(t, b)
}
