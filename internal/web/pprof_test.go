package web

import (
	"bytes"
	"compress/gzip"
	"io"
	"testing"

	"mhp/internal/agg"
)

// fields decodes one protobuf message level: field number -> raw values (varints as uint64, bytes as []byte).
func fields(t *testing.T, b []byte) map[int][]any {
	out := map[int][]any{}
	for len(b) > 0 {
		key, n := uvarint(b)
		b = b[n:]
		switch key & 7 {
		case 0:
			v, n := uvarint(b)
			b = b[n:]
			out[int(key>>3)] = append(out[int(key>>3)], v)
		case 2:
			l, n := uvarint(b)
			b = b[n:]
			out[int(key>>3)] = append(out[int(key>>3)], b[:l])
			b = b[l:]
		default:
			t.Fatalf("wire type %d", key&7)
		}
	}
	return out
}

func uvarint(b []byte) (uint64, int) {
	var v uint64
	for i, c := range b {
		v |= uint64(c&0x7f) << (7 * i)
		if c < 0x80 {
			return v, i + 1
		}
	}
	return 0, 0
}

func TestWritePprof(t *testing.T) {
	stacks := []agg.WeightedStack{
		{Frames: []string{"main", "dispatch_command", "my_malloc"}, Value: 3000, N: 3, Area: "SQL"},
		{Frames: []string{"main", "buf_pool_init"}, Value: -500, N: 1},
		{Frames: []string{"main", "nothing"}, Value: 0},
	}
	var buf bytes.Buffer
	if err := WritePprof(&buf, stacks, PprofOpts{Metric: "range_net", Comments: []string{"test"}}); err != nil {
		t.Fatal(err)
	}
	z, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(z)
	p := fields(t, raw)
	var strs []string
	for _, s := range p[6] {
		strs = append(strs, string(s.([]byte)))
	}
	if strs[0] != "" {
		t.Fatalf("string table must start with \"\": %q", strs)
	}
	if len(p[1]) != 2 || len(p[2]) != 2 || len(p[4]) != 4 || len(p[5]) != 4 {
		t.Fatalf("sample types %d, samples %d, locations %d, functions %d", len(p[1]), len(p[2]), len(p[4]), len(p[5]))
	}
	st := fields(t, p[1][0].([]byte))
	if strs[st[1][0].(uint64)] != "net_space" || strs[st[2][0].(uint64)] != "bytes" {
		t.Errorf("sample type %v", st)
	}
	s0 := fields(t, p[2][0].([]byte))
	ids := s0[1][0].([]byte)
	if len(ids) != 3 || ids[0] != 1 { // leaf first: my_malloc got location 1
		t.Errorf("location ids %v", ids)
	}
	fn := fields(t, p[5][0].([]byte))
	if strs[fn[2][0].(uint64)] != "my_malloc" {
		t.Errorf("first function %q", strs[fn[2][0].(uint64)])
	}
	vals := s0[2][0].([]byte)
	if v, _ := uvarint(vals); v != 3000 {
		t.Errorf("value %d", v)
	}
	lb := fields(t, s0[3][0].([]byte))
	if strs[lb[1][0].(uint64)] != "subsystem" || strs[lb[2][0].(uint64)] != "SQL" {
		t.Errorf("label %v", lb)
	}
	s1 := fields(t, p[2][1].([]byte))
	if v, _ := uvarint(s1[2][0].([]byte)); int64(v) != -500 {
		t.Errorf("negative value %d", int64(v))
	}
	if strs[p[13][0].(uint64)] != "test" || strs[p[14][0].(uint64)] != "net_space" {
		t.Error("comment / default sample type")
	}
}
