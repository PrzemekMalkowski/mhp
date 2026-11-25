package web

import (
	"fmt"
	"hash/fnv"
	"html"
	"io"
	"regexp"
	"sort"
	"strings"

	"github.com/PrzemekMalkowski/mhp/internal/agg"
)

// allocWrapper mirrors WRT in static/index.html: allocator frames hidden by "hide alloc wrappers".
var allocWrapper = regexp.MustCompile(`^(_int_malloc|_int_realloc|__libc_malloc|malloc|calloc|realloc|free|posix_memalign|aligned_alloc|memalign|operator new|operator delete|my_malloc|my_realloc|my_raw_malloc|my_raw_realloc|my_internal_malloc|my_internal_realloc|my_memdup|my_strdup|my_once_alloc|__libc_|ut::detail::|ut::.*(alloc|new)|\[anon mmap\]|std::__new_allocator|std::allocator|Stateful_allocator|Ut_allocator)`)

type FlameOpts struct {
	Title, Subtitle string
	Callers         bool // invert: leaf (allocating function / faulting mapping) at the top
	HideWrappers    bool
	Unit            string // "bytes" formats values as KiB/MiB
}

type fnode struct {
	name     string
	v        int64
	children map[string]*fnode
}

// prepare applies the export options to root-first stacks and drops non-positive values (shrinking stacks in a
// growth window cannot be drawn as widths); it returns the stacks to draw and the bytes dropped.
func prepare(stacks []agg.WeightedStack, o FlameOpts) ([][]string, []int64, int64) {
	var out [][]string
	var vals []int64
	var neg int64
	for _, st := range stacks {
		if st.Value <= 0 {
			neg += st.Value
			continue
		}
		fr := st.Frames
		if o.HideWrappers {
			kept := make([]string, 0, len(fr))
			for _, f := range fr {
				if !allocWrapper.MatchString(f) {
					kept = append(kept, f)
				}
			}
			fr = kept
		}
		if o.Callers {
			rev := make([]string, len(fr))
			for i, f := range fr {
				rev[len(fr)-1-i] = f
			}
			fr = rev
		}
		out = append(out, fr)
		vals = append(vals, st.Value)
	}
	return out, vals, neg
}

// Folded writes flamegraph.pl / speedscope folded stacks (root-first, ';'-joined, value).
func Folded(w io.Writer, stacks []agg.WeightedStack, o FlameOpts) {
	fr, vals, _ := prepare(stacks, o)
	for i, f := range fr {
		fmt.Fprintf(w, "%s %d\n", strings.ReplaceAll(strings.Join(f, ";"), " ", "_"), vals[i])
	}
}

func fmtValue(v int64, unit string) string {
	if unit != "bytes" {
		return fmt.Sprint(v)
	}
	switch f := float64(v); {
	case f >= 1<<30:
		return fmt.Sprintf("%.2f GiB", f/(1<<30))
	case f >= 1<<20:
		return fmt.Sprintf("%.1f MiB", f/(1<<20))
	case f >= 1<<10:
		return fmt.Sprintf("%.1f KiB", f/(1<<10))
	}
	return fmt.Sprintf("%d B", v)
}

// frameColor follows flamegraph.pl's warm palette, hashed by name so a function keeps its color across exports;
// pseudo-frames ([fault: ...], [anon mmap]) are blue-grey.
func frameColor(name string) string {
	if strings.HasPrefix(name, "[") {
		return "rgb(150,175,200)"
	}
	h := fnv.New32a()
	h.Write([]byte(name))
	x := h.Sum32()
	return fmt.Sprintf("rgb(%d,%d,%d)", 205+int(x%50), int((x>>8)%230), int((x>>16)%55))
}

const (
	svgWidth = 1600
	rowH     = 17
	charW    = 7.0 // approx. width of a 12px monospace character
	topPad   = 64
)

func label(name string, px float64) string {
	n := int((px - 6) / charW)
	if n < 3 {
		return ""
	}
	if len([]rune(name)) <= n {
		return name
	}
	return string([]rune(name)[:n-2]) + ".."
}

// FlameSVG writes a standalone, interactive flame graph (root at the top; click to zoom, search, tooltips).
func FlameSVG(w io.Writer, stacks []agg.WeightedStack, o FlameOpts) {
	fr, vals, neg := prepare(stacks, o)
	root := &fnode{name: "all", children: map[string]*fnode{}}
	for i, f := range fr {
		n := root
		n.v += vals[i]
		for _, name := range f {
			c := n.children[name]
			if c == nil {
				c = &fnode{name: name, children: map[string]*fnode{}}
				n.children[name] = c
			}
			c.v += vals[i]
			n = c
		}
	}
	type box struct {
		n     *fnode
		x, w  float64 // fractions of the total
		depth int
	}
	var boxes []box
	maxDepth := 0
	var walk func(n *fnode, x float64, depth int)
	walk = func(n *fnode, x float64, depth int) {
		if root.v == 0 {
			return
		}
		wf := float64(n.v) / float64(root.v)
		if wf*svgWidth < 0.3 {
			return
		}
		boxes = append(boxes, box{n: n, x: x, w: wf, depth: depth})
		maxDepth = max(maxDepth, depth)
		kids := make([]*fnode, 0, len(n.children))
		for _, c := range n.children {
			kids = append(kids, c)
		}
		sort.Slice(kids, func(i, j int) bool {
			return kids[i].v > kids[j].v || kids[i].v == kids[j].v && kids[i].name < kids[j].name
		})
		for _, c := range kids {
			walk(c, x, depth+1)
			x += float64(c.v) / float64(root.v)
		}
	}
	walk(root, 0, 0)

	height := topPad + (maxDepth+1)*rowH + 24
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.1" width="%d" height="%d" viewBox="0 0 %d %d" font-family="ui-monospace,Menlo,Consolas,monospace" font-size="12">
<style>
 g.f rect{stroke:#fff;stroke-width:0.5} g.f:hover rect{stroke:#000;stroke-width:1} g.f{cursor:pointer}
 g.f text{pointer-events:none;fill:#000} g.f.dim rect{opacity:0.45} g.f.hit rect{fill:rgb(230,0,230)}
 .ui{cursor:pointer;fill:#246} .ui:hover{text-decoration:underline}
</style>
<rect width="100%%" height="100%%" fill="#fbfbf8"/>
<text x="%d" y="22" font-size="16" text-anchor="middle" font-weight="bold">%s</text>
<text x="%d" y="40" text-anchor="middle" fill="#555">%s</text>
<text id="reset" class="ui" x="10" y="58" visibility="hidden">Reset zoom</text>
<text id="search" class="ui" x="%d" y="58" text-anchor="end">Search</text>
<text id="matched" x="%d" y="%d" text-anchor="end" fill="#555"></text>
<text id="details" x="10" y="%d" fill="#333"> </text>
`, svgWidth, height, svgWidth, height, svgWidth/2, html.EscapeString(o.Title), svgWidth/2, html.EscapeString(o.Subtitle),
		svgWidth-10, svgWidth-10, height-6, height-6)
	for _, b := range boxes {
		px := b.w * svgWidth
		info := fmt.Sprintf("%s (%s, %.2f%%)", b.n.name, fmtValue(b.n.v, o.Unit), 100*b.w)
		y := topPad + b.depth*rowH
		fmt.Fprintf(w, `<g class="f" data-x="%.9f" data-w="%.9f" data-d="%d" data-n="%s"><title>%s</title>`+
			`<rect x="%.2f" y="%d" width="%.2f" height="%d" rx="2" fill="%s"/><text x="%.2f" y="%d">%s</text></g>`+"\n",
			b.x, b.w, b.depth, html.EscapeString(b.n.name), html.EscapeString(info),
			b.x*svgWidth, y, max(px-0.5, 0.1), rowH-1, frameColor(b.n.name), b.x*svgWidth+3, y+rowH-5,
			html.EscapeString(label(b.n.name, px)))
	}
	if neg != 0 {
		fmt.Fprintf(w, `<text x="10" y="%d" fill="#a33">%s shrank in this window (not drawn)</text>`+"\n", height-24,
			html.EscapeString(fmtValue(-neg, o.Unit)))
	}
	fmt.Fprintf(w, `<script><![CDATA[
const W=%d, CW=%g, fr=[...document.querySelectorAll('g.f')], det=document.getElementById('details');
function lab(n,px){const k=Math.floor((px-6)/CW);return k<3?'':n.length<=k?n:n.slice(0,k-2)+'..'}
function place(g,x,w){const r=g.querySelector('rect'),t=g.querySelector('text');
 r.setAttribute('x',x*W);r.setAttribute('width',Math.max(w*W-0.5,0.1));t.setAttribute('x',x*W+3);t.textContent=lab(g.dataset.n,w*W)}
function zoom(z){const x=+z.dataset.x,w=+z.dataset.w,d=+z.dataset.d,e=1e-9;
 for(const g of fr){const gx=+g.dataset.x,gw=+g.dataset.w,gd=+g.dataset.d;g.classList.remove('dim');
  if(gd<d&&gx<=x+e&&gx+gw>=x+w-e){g.style.display='';g.classList.add('dim');place(g,0,1)}
  else if(gd>=d&&gx>=x-e&&gx+gw<=x+w+e){g.style.display='';place(g,(gx-x)/w,gw/w)}
  else g.style.display='none'}
 document.getElementById('reset').setAttribute('visibility',d?'visible':'hidden')}
for(const g of fr){g.onclick=()=>zoom(g);g.onmouseover=()=>det.textContent=g.querySelector('title').textContent;g.onmouseout=()=>det.textContent=' '}
document.getElementById('reset').onclick=()=>zoom(fr[0]);
document.getElementById('search').onclick=()=>{const q=prompt('Search (regular expression)','');let re;
 try{re=q?new RegExp(q):null}catch(err){return}
 let hit=0;const root=+fr[0].dataset.w,spans=[];
 for(const g of fr){const m=re&&re.test(g.dataset.n);g.classList.toggle('hit',!!m);if(m)spans.push([+g.dataset.x,+g.dataset.w])}
 spans.sort((a,b)=>a[0]-b[0]);let end=-1;for(const [x,w] of spans){if(x>=end){hit+=w;end=x+w}else if(x+w>end){hit+=x+w-end;end=x+w}}
 document.getElementById('matched').textContent=re?'Matched: '+(100*hit/root).toFixed(1)+'%%':''};
]]></script>
</svg>
`, svgWidth, charW)
}
