package web

import (
	"context"
	"testing"
	"time"

	"github.com/PrzemekMalkowski/mhp/internal/agg"
	"github.com/PrzemekMalkowski/mhp/internal/live"
)

func TestPeaks(t *testing.T) {
	hub := live.NewHub(100)
	a := agg.New(nil, 60)
	srv := &Server{Hub: hub, Dump: a.Export}
	p := &Peaks{Srv: srv, CgroupPct: 90, MinAge: time.Second, MinGap: time.Millisecond}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.Run(ctx)
	time.Sleep(50 * time.Millisecond) // subscribed
	const G = 1 << 30
	t0 := int64(1_000_000)
	rss := []int64{1, 2, 3, 4, 5, 5, 5, 5, 4, 3, 4, 4, 4, 4}
	for i, r := range rss {
		hub.Publish(live.View{T: t0 + int64(i)*1000, Proc: map[string]int64{"rss": r * G / 4, "cgroup_limit": 2 * G}})
		time.Sleep(30 * time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	cs := p.List()
	kinds := map[string]PeakCopy{}
	for _, c := range cs {
		kinds[c.Kind] = c
	}
	pk, ok := kinds["peak"]
	if !ok || pk.RSS != 5*G/4 || pk.snap == nil {
		t.Errorf("peak copy: %+v (all: %+v)", pk, cs)
	}
	// 1.25 GiB of 2 GiB never reaches 90%: no cgroup copy
	if _, ok := kinds["cgroup"]; ok {
		t.Errorf("unexpected cgroup copy")
	}
	hub.Publish(live.View{T: t0 + 20000, Proc: map[string]int64{"rss": 19 * G / 10, "cgroup_limit": 2 * G}})
	time.Sleep(300 * time.Millisecond)
	for _, c := range p.List() {
		if c.Kind == "cgroup" {
			return
		}
	}
	t.Error("no cgroup copy at 95% of the limit")
}
