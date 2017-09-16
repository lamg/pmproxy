package pmproxy

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestLogString(t *testing.T) {
	tm := time.Unix(0, 0)
	l := &Log{
		User:        "lamg",
		Addr:        cocoIP,
		Meth:        "GET",
		URI:         "https://facebook.com/coco",
		Proto:       "HTTP/1.1",
		StatusCode:  200,
		RespSize:    1024,
		Time:        tm,
		Elapsed:     time.Nanosecond,
		Action:      "TCP_MISS",
		Hierarchy:   "DIRECT",
		From:        pepeIP,
		ContentType: "text/html",
	}
	sl, wt := l.String(), fmt.Sprintf("        0.000      1 %s TCP_MISS/200 1024 GET https://facebook.com/coco lamg DIRECT/%s text/html", cocoIP, pepeIP)
	require.True(t, sl == wt, "%s ≠ %s && len(sl): %d && len(wt): %d", sl, wt, len(sl), len(wt))
}
