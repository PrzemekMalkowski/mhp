package web

import (
	"compress/gzip"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"mhp/internal/agg"
	"mhp/internal/live"
	"mhp/internal/sym"
)

// An offline copy is the UI page plus a Snapshot of everything its requests read: the view history (chart,
// tables), the aggregator's stacks and timeline (time ranges, Explore, reports), report metadata and the source
// locations of the frames. The page runs this package compiled to WebAssembly (cmd/mhpwasm) on the restored
// state, so every query gives the same answer as the live mhp.

const snapshotVersion = 1

type Snapshot struct {
	Version int
	Created int64  // unix ms
	Info    []byte // /info JSON
	History []byte // /history JSON
	Meta    [][2]string
	Repos   *SourceRepos
	Sources map[string]sym.SourceLoc
	Agg     *agg.Dump
}

// SourceBudget bounds the time spent resolving source locations (one llvm-symbolizer query per new function).
var SourceBudget = 20 * time.Second

// Snapshot captures the server's current state.
func (s *Server) Snapshot() (*Snapshot, error) {
	sn, info, err := s.snapshotState()
	if err != nil {
		return nil, err
	}
	return sn, s.finishSnapshot(sn, info)
}

// snapshotState captures what the copy shows (aggregator, view history, metadata): fast, so a peak copy holds the
// moment it was taken for. finishSnapshot adds the source locations, which can take seconds.
func (s *Server) snapshotState() (*Snapshot, map[string]any, error) {
	if s.Dump == nil {
		return nil, nil, fmt.Errorf("no aggregator to export")
	}
	sn := &Snapshot{Version: snapshotVersion, Created: time.Now().UnixMilli(), Repos: s.Repos, Agg: s.Dump(),
		Sources: map[string]sym.SourceLoc{}}
	var err error
	if sn.History, err = json.Marshal(s.Hub.History()); err != nil {
		return nil, nil, err
	}
	info := map[string]any{}
	if s.Info != nil {
		if m, ok := s.Info().(map[string]any); ok {
			info = m
		}
	}
	if s.Meta != nil {
		sn.Meta = s.Meta()
	}
	return sn, info, nil
}

func (s *Server) finishSnapshot(sn *Snapshot, info map[string]any) (err error) {
	if s.Source != nil {
		deadline := time.Now().Add(SourceBudget)
		for _, f := range sn.Agg.Frames {
			if time.Now().After(deadline) {
				info["offline_sources_cut"] = true
				break
			}
			if loc, ok := s.Source(f); ok {
				sn.Sources[f] = loc
			}
		}
	}
	sn.Info, err = json.Marshal(info)
	return err
}

func (sn *Snapshot) Encode(w io.Writer) error {
	z, _ := gzip.NewWriterLevel(w, gzip.BestSpeed)
	if err := gob.NewEncoder(z).Encode(sn); err != nil {
		return err
	}
	return z.Close()
}

func DecodeSnapshot(r io.Reader) (*Snapshot, error) {
	z, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	var sn Snapshot
	if err := gob.NewDecoder(z).Decode(&sn); err != nil {
		return nil, err
	}
	if sn.Version != snapshotVersion {
		return nil, fmt.Errorf("snapshot version %d, this page reads %d", sn.Version, snapshotVersion)
	}
	return &sn, nil
}

// OfflineServer serves a Snapshot: the same handlers, backed by the restored state, with no tracer and no live
// events.
func OfflineServer(sn *Snapshot) (*Server, error) {
	var views []live.View
	if err := json.Unmarshal(sn.History, &views); err != nil {
		return nil, err
	}
	hub := live.NewHub(max(2, len(views)))
	for _, v := range views {
		hub.Publish(v)
	}
	info := map[string]any{}
	if err := json.Unmarshal(sn.Info, &info); err != nil {
		return nil, err
	}
	info["tracer"], info["arenas"] = false, false
	info["offline"] = map[string]any{"created": sn.Created, "views": len(views), "ticks": len(sn.Agg.Ticks), "sources": len(sn.Sources)}
	a := agg.Restore(sn.Agg)
	meta := append([][2]string(nil), sn.Meta...)
	return &Server{Hub: hub, Folded: a.Folded, Stacks: a.Stacks, Range: a.Range, RangeThreads: a.RangeThreads,
		Meta: func() [][2]string { return meta }, Info: func() any { return info }, Repos: sn.Repos,
		Source: func(f string) (sym.SourceLoc, bool) { l, ok := sn.Sources[f]; return l, ok }}, nil
}
