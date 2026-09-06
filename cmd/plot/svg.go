package main

import (
	"fmt"
	"math"
	"strings"
)

// SVG output, hand-rolled.
//
// WHY NO PLOTTING LIBRARY. SKILL.md requires every dependency beyond the base
// toolchain to be flagged and justified, and a chart renderer is a large one to
// take on for a handful of line charts. SVG is text, needs nothing, renders in
// any browser, and drops into Overleaf via \includesvg or converts with one
// command. A CSV goes beside every chart, so nothing here is locked in: whoever
// writes the paper can re-plot in pgfplots or matplotlib from the same numbers.
//
// The charts are deliberately plain. These are working figures for reading
// results, not the final artwork — and a plot that looks finished invites less
// scrutiny of the numbers under it.

const (
	svgW, svgH                     = 900, 520
	padL, padR, padT, padB         = 90, 240, 56, 64
	plotW, plotH                   = svgW - padL - padR, svgH - padT - padB
	tickLen, markerR, legendLineLn = 5, 3.0, 22
)

// palette is colour-blind-safe (Okabe-Ito). Series are also distinguished by
// dash pattern, so the figure survives greyscale printing — a chart that needs
// colour to be read is one a reviewer may not be able to read.
var palette = []string{
	"#0072B2", "#D55E00", "#009E73", "#CC79A7",
	"#E69F00", "#56B4E9", "#F0E442", "#000000",
}

var dashes = []string{"", "6,3", "2,3", "8,3,2,3", "1,3", "10,4"}

type axis struct {
	min, max float64
	log      bool
}

func newAxis(lo, hi float64, log bool) axis {
	if log {
		// A log axis cannot show zero or negative values. Clamp to the smallest
		// positive value rather than dropping points silently.
		if lo <= 0 {
			lo = math.SmallestNonzeroFloat64
		}
		if hi <= lo {
			hi = lo * 10
		}
		return axis{min: math.Log10(lo), max: math.Log10(hi), log: true}
	}
	if hi == lo {
		// A flat series is a real outcome — Exp 3 hopes for one. Give it a band
		// so it renders as a line rather than collapsing to the axis.
		d := math.Abs(hi) * 0.1
		if d == 0 {
			d = 1
		}
		lo, hi = lo-d, hi+d
	}
	return axis{min: lo, max: hi}
}

func (a axis) pos(v float64) float64 {
	if a.log {
		if v <= 0 {
			return 0
		}
		v = math.Log10(v)
	}
	if a.max == a.min {
		return 0.5
	}
	return (v - a.min) / (a.max - a.min)
}

// renderSVG draws one chart.
func renderSVG(c chart) string {
	var b strings.Builder

	xs, ys := bounds(c.Series)
	ax := newAxis(xs[0], xs[1], c.XLog)
	ay := newAxis(ys[0], ys[1], c.YLog)

	px := func(v float64) float64 { return padL + ax.pos(v)*plotW }
	py := func(v float64) float64 { return padT + (1-ay.pos(v))*plotH }

	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" font-family="system-ui,-apple-system,Segoe UI,sans-serif">`,
		svgW, svgH, svgW, svgH)
	fmt.Fprint(&b, `<rect width="100%" height="100%" fill="#ffffff"/>`)

	fmt.Fprintf(&b, `<text x="%d" y="26" font-size="16" font-weight="600" fill="#111">%s</text>`,
		padL, esc(c.Title))

	// Axes and gridlines.
	fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" fill="none" stroke="#bbb"/>`,
		padL, padT, plotW, plotH)

	for _, t := range ticks(ax) {
		x := px(t)
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="#eee"/>`,
			x, padT, x, padT+plotH)
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke="#666"/>`,
			x, padT+plotH, x, padT+plotH+tickLen)
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" font-size="11" fill="#333" text-anchor="middle">%s</text>`,
			x, padT+plotH+tickLen+14, esc(fmtNum(t)))
	}
	for _, t := range ticks(ay) {
		y := py(t)
		fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#eee"/>`,
			padL, y, padL+plotW, y)
		fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%d" y2="%.1f" stroke="#666"/>`,
			padL-tickLen, y, padL, y)
		fmt.Fprintf(&b, `<text x="%d" y="%.1f" font-size="11" fill="#333" text-anchor="end">%s</text>`,
			padL-tickLen-4, y+4, esc(fmtNum(t)))
	}

	fmt.Fprintf(&b, `<text x="%.0f" y="%d" font-size="12" fill="#333" text-anchor="middle">%s</text>`,
		float64(padL)+plotW/2, svgH-18, esc(c.XLabel))
	fmt.Fprintf(&b, `<text transform="translate(18,%.0f) rotate(-90)" font-size="12" fill="#333" text-anchor="middle">%s</text>`,
		float64(padT)+plotH/2, esc(c.YLabel))

	// Series.
	for i, s := range c.Series {
		colour := palette[i%len(palette)]
		dash := dashes[i%len(dashes)]

		// Spread band first, so markers sit on top of it.
		for _, p := range s.Points {
			if p.N < 2 || p.Max == p.Min {
				continue
			}
			fmt.Fprintf(&b, `<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="%s" stroke-width="1" opacity="0.45"/>`,
				px(p.X), py(p.Min), px(p.X), py(p.Max), colour)
		}

		var d strings.Builder
		for j, p := range s.Points {
			cmd := "L"
			if j == 0 {
				cmd = "M"
			}
			fmt.Fprintf(&d, "%s%.1f,%.1f ", cmd, px(p.X), py(p.Mean))
		}
		fmt.Fprintf(&b, `<path d="%s" fill="none" stroke="%s" stroke-width="2" stroke-dasharray="%s"/>`,
			strings.TrimSpace(d.String()), colour, dash)

		for _, p := range s.Points {
			// A single-observation point is drawn hollow. It is not a
			// measurement with a spread, and the figure should not imply it is.
			fill := colour
			if p.N < 2 {
				fill = "#ffffff"
			}
			fmt.Fprintf(&b, `<circle cx="%.1f" cy="%.1f" r="%.1f" fill="%s" stroke="%s" stroke-width="1.5"/>`,
				px(p.X), py(p.Mean), markerR, fill, colour)
		}
	}

	// Legend.
	ly := padT + 4
	for i, s := range c.Series {
		colour := palette[i%len(palette)]
		dash := dashes[i%len(dashes)]
		lx := padL + plotW + 16
		fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="%s" stroke-width="2" stroke-dasharray="%s"/>`,
			lx, ly, lx+legendLineLn, ly, colour, dash)
		fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="11" fill="#222">%s</text>`,
			lx+legendLineLn+6, ly+4, esc(truncate(s.Label(), 30)))
		ly += 17
	}

	// Caveats, and the honesty note about single observations.
	notes := append([]string(nil), c.Caveats...)
	if single := totalSingle(c.Series); single > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d point(s) are a SINGLE repetition (hollow markers) — no spread is known for them", single))
	}
	ny := padT + plotH + 34
	for _, n := range notes {
		for _, line := range wrap(n, 118) {
			if ny > svgH-6 {
				break
			}
			fmt.Fprintf(&b, `<text x="%d" y="%d" font-size="10" fill="#666">%s</text>`,
				padL, ny, esc(line))
			ny += 12
		}
	}

	b.WriteString(`</svg>`)
	return b.String()
}

func totalSingle(ss []Series) int {
	n := 0
	for _, s := range ss {
		n += s.SingleObservationPoints()
	}
	return n
}

func bounds(ss []Series) (xs, ys [2]float64) {
	first := true
	for _, s := range ss {
		for _, p := range s.Points {
			lo, hi := p.Mean, p.Mean
			if p.N > 1 {
				lo, hi = p.Min, p.Max
			}
			if first {
				xs = [2]float64{p.X, p.X}
				ys = [2]float64{lo, hi}
				first = false
				continue
			}
			xs[0] = math.Min(xs[0], p.X)
			xs[1] = math.Max(xs[1], p.X)
			ys[0] = math.Min(ys[0], lo)
			ys[1] = math.Max(ys[1], hi)
		}
	}
	if first {
		return [2]float64{0, 1}, [2]float64{0, 1}
	}
	return xs, ys
}

// ticks returns axis tick values: decades on a log axis, five steps otherwise.
func ticks(a axis) []float64 {
	var out []float64
	if a.log {
		for e := math.Floor(a.min); e <= math.Ceil(a.max); e++ {
			v := math.Pow(10, e)
			if math.Log10(v) >= a.min-1e-9 && math.Log10(v) <= a.max+1e-9 {
				out = append(out, v)
			}
		}
		if len(out) < 2 {
			out = []float64{math.Pow(10, a.min), math.Pow(10, a.max)}
		}
		return out
	}
	const n = 5
	step := (a.max - a.min) / n
	for i := 0; i <= n; i++ {
		out = append(out, a.min+step*float64(i))
	}
	return out
}

func fmtNum(v float64) string {
	switch {
	case v == 0:
		return "0"
	case math.Abs(v) >= 1e6 || (math.Abs(v) < 1e-3 && v != 0):
		return fmt.Sprintf("%.0e", v)
	case v == math.Trunc(v):
		return fmt.Sprintf("%.0f", v)
	case math.Abs(v) < 1:
		return fmt.Sprintf("%.3g", v)
	default:
		return fmt.Sprintf("%.4g", v)
	}
}

func esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "…"
}

func wrap(s string, width int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	cur := words[0]
	for _, w := range words[1:] {
		if len(cur)+1+len(w) > width {
			lines = append(lines, cur)
			cur = w
			continue
		}
		cur += " " + w
	}
	return append(lines, cur)
}
