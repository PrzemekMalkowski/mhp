package shim

import (
	"os"
	"testing"
)

const sampleInfo = `<malloc version="1">
<heap nr="0">
<sizes>
  <size from="33" to="33" total="990" count="30"/>
  <size from="1041" to="1041" total="1041" count="1"/>
  <size from="532737" to="133025809" total="909063670" count="38"/>
  <unsorted from="8481" to="8481" total="8481" count="1"/>
</sizes>
<total type="fast" count="0" size="0"/>
<total type="rest" count="70" size="910074182"/>
<system type="current" size="1172496384"/>
<system type="max" size="1352585216"/>
<aspace type="total" size="1172496384"/>
<aspace type="mprotect" size="1172496384"/>
</heap>
<heap nr="1">
<sizes>
</sizes>
<total type="fast" count="0" size="0"/>
<total type="rest" count="1" size="4096"/>
<system type="current" size="135168"/>
<system type="max" size="135168"/>
<aspace type="total" size="135168"/>
<aspace type="mprotect" size="135168"/>
<aspace type="subheaps" size="2"/>
</heap>
<total type="fast" count="0" size="0"/>
<total type="rest" count="71" size="910078278"/>
<total type="mmap" count="3" size="3000000"/>
<system type="current" size="1172631552"/>
<system type="max" size="1352720384"/>
<aspace type="total" size="1172631552"/>
<aspace type="mprotect" size="1172631552"/>
</malloc>
`

func TestParseMallocInfo(t *testing.T) {
	st, cut := ParseMallocInfo([]byte(sampleInfo))
	if cut || len(st.Arenas) != 2 {
		t.Fatalf("cut %v, %d arenas", cut, len(st.Arenas))
	}
	a := st.Arenas[0]
	if a.Size != 1172496384 || a.MaxSize != 1352585216 || a.Free != 910074182 || a.FastFree != 0 || a.FreeChunks != 70 {
		t.Errorf("arena 0: %+v", a)
	}
	if a.FreeSmall != 990 || a.FreeMid != 1041+8481 || a.FreeLarge != 909063670 || a.Largest != 133025809 ||
		a.Top != 1000000 { // rest minus the bins: the top chunk
		t.Errorf("arena 0 size classes: %+v", a)
	}
	if b := st.Arenas[1]; b.N != 1 || b.Subheaps != 2 || b.Free != 4096 || b.Top != 4096 {
		t.Errorf("arena 1: %+v", b)
	}
	if st.Size != 1172631552 || st.Free != 910078278 || st.Top != 1004096 || st.MmapChunks != 3 || st.Mmapped != 3000000 {
		t.Errorf("totals: %+v", st)
	}

	// cut inside the second arena: the first is kept, totals come from it
	st, cut = ParseMallocInfo([]byte(sampleInfo[:len(sampleInfo)/2+200]))
	if !cut || len(st.Arenas) != 1 || st.Size != 1172496384 || !st.Truncated {
		t.Errorf("truncated: cut %v %+v", cut, st)
	}
}

// TestParseMallocInfoReal reads a real dump when one is around (98 arenas of a Percona Server under MyRocks).
func TestParseMallocInfoReal(t *testing.T) {
	b, err := os.ReadFile("../../reports/malloc_info-ps8.4.11-myrocks-blob-glibc-peak.xml")
	if err != nil {
		t.Skip(err)
	}
	st, cut := ParseMallocInfo(b)
	var free int64
	for _, a := range st.Arenas {
		free += a.Free
	}
	if cut || len(st.Arenas) < 10 || st.Free != free || st.Size != 37568077824 {
		t.Errorf("cut %v, %d arenas, free %d vs %d, size %d", cut, len(st.Arenas), st.Free, free, st.Size)
	}
}
