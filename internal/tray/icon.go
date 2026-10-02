package tray

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
	"strconv"
	"strings"
	"sync"
)

// Icon draws the notification-area icon for a health, as a PNG of size×size
// pixels — the form Windows accepts directly as an icon image.
//
// THE SSL.COM PINWHEEL, WITH THE STATE AS A BADGE. The mark is the product's,
// so it is drawn as the brand draws it — one ink, no colour of its own — and
// the state rides in the bottom-right corner, the way Windows' own sync icons
// carry theirs. When all is well there is NO badge: the plain mark is what a
// healthy machine looks like, and a badge appearing is the signal.
//
// THE INK FOLLOWS THE TASKBAR. The brand's near-black vanishes on a dark
// taskbar, which is the Windows 11 default, so onDark draws the mark in white.
//
// SHAPE, NOT ONLY COLOUR. An exclamation mark, a bar and a ring, so the badge
// is legible to someone who cannot tell the amber from the red.
func Icon(h Health, size int, onDark bool) []byte {
	ink := color.NRGBA{brandInk[0], brandInk[1], brandInk[2], 255}
	if onDark {
		ink = color.NRGBA{255, 255, 255, 255}
	}
	fill, hasBadge := badgeColour(h)

	mark := pinwheel()
	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const ss = 4 // supersamples per axis, for anti-aliased edges
	s := float64(size)

	// Badge geometry in unit coordinates ([0,1] across the icon).
	const (
		bx, by = 0.70, 0.70 // centre
		br     = 0.30       // radius
		gap    = 0.07       // transparent ring that separates it from the mark
	)

	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					ux := (float64(x) + (float64(sx)+0.5)/ss) / s
					uy := (float64(y) + (float64(sy)+0.5)/ss) / s
					var c color.NRGBA
					var on bool
					d := math.Hypot(ux-bx, uy-by)
					switch {
					case hasBadge && d <= br:
						c, on = fill, true
						// The glyph, in the badge's own [-1,1] space.
						if glyph(h, (ux-bx)/br, (uy-by)/br, s*br) {
							c = color.NRGBA{255, 255, 255, 255}
						}
					case hasBadge && d <= br+gap:
						// Cut out, so the badge reads against the arm behind it.
					default:
						if mark.contains(ux, uy) {
							c, on = ink, true
						}
					}
					if on {
						r += float64(c.R)
						g += float64(c.G)
						b += float64(c.B)
						a++
					}
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{
				R: uint8(math.Round(r / a)), G: uint8(math.Round(g / a)), B: uint8(math.Round(b / a)),
				A: uint8(math.Round(a / (ss * ss) * 255)),
			})
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// glyph reports whether a point in the badge's [-1,1] space is on its symbol.
func glyph(h Health, x, y, badgePx float64) bool {
	// A fixed fraction of the badge, with a floor of about a pixel and a half
	// so the stroke survives at 16 px, where the whole badge is ten pixels.
	w := math.Max(0.20, 1.6/badgePx)
	switch h {
	case Attention: // an exclamation mark
		return segment(x, y, 0, -0.55, 0, 0.05) < w*0.9 || math.Hypot(x, y-0.50) < w
	case Problem: // a no-entry bar
		return segment(x, y, -0.55, 0, 0.55, 0) < w*1.1
	default: // Unknown: a ring — the state cannot be read
		return math.Hypot(x, y) < 0.55 && math.Hypot(x, y) > 0.55-2*w
	}
}

// badgeColour is the badge for a health, and whether there is one at all.
func badgeColour(h Health) (color.NRGBA, bool) {
	switch h {
	case Good:
		return color.NRGBA{}, false
	case Attention:
		return color.NRGBA{0xd9, 0x77, 0x06, 255}, true
	case Problem:
		return color.NRGBA{0xc8, 0x22, 0x22, 255}, true
	default:
		return color.NRGBA{0x6b, 0x72, 0x80, 255}, true
	}
}

// segment is the distance from a point to the line segment a–b.
func segment(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

// ── the mark ─────────────────────────────────────────────────────────────────

// shape is the pinwheel flattened to polygons, in unit coordinates.
type shape struct{ polys [][]pt }

type pt struct{ x, y float64 }

var (
	pinwheelOnce sync.Once
	pinwheelMark shape
)

// pinwheel parses the paths once and fits the mark into the unit square with a
// small margin, centred — the paths' own box is not quite square.
func pinwheel() shape {
	pinwheelOnce.Do(func() {
		var polys [][]pt
		for _, d := range pinwheelPaths {
			polys = append(polys, parsePath(d)...)
		}
		minX, minY, maxX, maxY := math.Inf(1), math.Inf(1), math.Inf(-1), math.Inf(-1)
		for _, p := range polys {
			for _, q := range p {
				minX, minY = math.Min(minX, q.x), math.Min(minY, q.y)
				maxX, maxY = math.Max(maxX, q.x), math.Max(maxY, q.y)
			}
		}
		const margin = 0.03
		span := math.Max(maxX-minX, maxY-minY)
		scale := (1 - 2*margin) / span
		offX := margin + ((1-2*margin)-(maxX-minX)*scale)/2
		offY := margin + ((1-2*margin)-(maxY-minY)*scale)/2
		for _, p := range polys {
			for i := range p {
				p[i] = pt{offX + (p[i].x-minX)*scale, offY + (p[i].y-minY)*scale}
			}
		}
		pinwheelMark = shape{polys: polys}
	})
	return pinwheelMark
}

// contains is the nonzero winding rule, which is SVG's default fill rule.
func (s shape) contains(x, y float64) bool {
	winding := 0
	for _, poly := range s.polys {
		for i := range poly {
			a, b := poly[i], poly[(i+1)%len(poly)]
			if a.y <= y {
				if b.y > y && cross(a, b, x, y) > 0 {
					winding++
				}
			} else if b.y <= y && cross(a, b, x, y) < 0 {
				winding--
			}
		}
	}
	return winding != 0
}

func cross(a, b pt, x, y float64) float64 { return (b.x-a.x)*(y-a.y) - (x-a.x)*(b.y-a.y) }

// parsePath reads the subset of SVG path data the mark uses — absolute M, L,
// H, V, C and Z — into polygons, flattening each cubic into short segments.
// Anything else is a change to the mark that this needs to learn about, and
// TestTheMarkUsesOnlyWhatTheParserReads says so.
func parsePath(d string) [][]pt {
	toks := tokenize(d)
	var (
		polys [][]pt
		cur   []pt
		pos   pt
		cmd   byte
	)
	num := func(i *int) float64 { v, _ := strconv.ParseFloat(toks[*i], 64); *i++; return v }
	for i := 0; i < len(toks); {
		if c := toks[i][0]; (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			cmd = c
			i++
		}
		switch cmd {
		case 'M':
			if len(cur) > 0 {
				polys = append(polys, cur)
			}
			pos = pt{num(&i), num(&i)}
			cur = []pt{pos}
			cmd = 'L' // further pairs after M are line-tos
		case 'L':
			pos = pt{num(&i), num(&i)}
			cur = append(cur, pos)
		case 'H':
			pos = pt{num(&i), pos.y}
			cur = append(cur, pos)
		case 'V':
			pos = pt{pos.x, num(&i)}
			cur = append(cur, pos)
		case 'C':
			c1, c2, end := pt{num(&i), num(&i)}, pt{num(&i), num(&i)}, pt{num(&i), num(&i)}
			const steps = 8
			for k := 1; k <= steps; k++ {
				t := float64(k) / steps
				u := 1 - t
				cur = append(cur, pt{
					u*u*u*pos.x + 3*u*u*t*c1.x + 3*u*t*t*c2.x + t*t*t*end.x,
					u*u*u*pos.y + 3*u*u*t*c1.y + 3*u*t*t*c2.y + t*t*t*end.y,
				})
			}
			pos = end
		case 'Z':
			if len(cur) > 0 {
				polys = append(polys, cur)
				cur = nil
			}
		default:
			i++ // unknown: skip, and let the test catch it
		}
	}
	if len(cur) > 0 {
		polys = append(polys, cur)
	}
	return polys
}

func tokenize(d string) []string {
	var toks []string
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			toks = append(toks, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(d); i++ {
		c := d[i]
		switch {
		case (c >= 'A' && c <= 'Z' && c != 'E') || (c >= 'a' && c <= 'z' && c != 'e'):
			flush()
			toks = append(toks, string(c))
		case c == ' ' || c == ',' || c == '\n' || c == '\t':
			flush()
		case c == '-' && b.Len() > 0 && !strings.HasSuffix(b.String(), "e") && !strings.HasSuffix(b.String(), "E"):
			flush()
			b.WriteByte(c)
		case c == '.' && strings.Contains(b.String(), "."):
			// "1.5.5" is two numbers in SVG path data.
			flush()
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	flush()
	return toks
}

// AppIcon draws the icon the agent's files carry — the .exe in Explorer, the
// Start-menu shortcut, Add/Remove Programs — as a PNG of size×size pixels.
//
// ON A TILE, unlike the notification-area icon. A file icon is one picture for
// every background it will ever sit on, and Explorer and the Start menu are
// each dark or light at the user's choice: the brand's ink vanishes on one and
// white on the other. So the mark is drawn white on a rounded square of the
// brand's ink, which reads on both — the way application icons usually solve
// the same problem.
func AppIcon(size int) []byte {
	tile := color.NRGBA{brandInk[0], brandInk[1], brandInk[2], 255}
	white := color.NRGBA{255, 255, 255, 255}
	mark := pinwheel()

	img := image.NewNRGBA(image.Rect(0, 0, size, size))
	const (
		ss     = 4
		radius = 0.20 // corner radius, as a fraction of the tile
	)
	// The margin between the tile's edge and the mark: generous where there
	// are pixels to spare, tight at the sizes Explorer's lists use, where a
	// generous margin leaves the mark too small to read.
	inset := 0.17
	if size <= 24 {
		inset = 0.10
	}
	s := float64(size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var r, g, b, a float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					ux := (float64(x) + (float64(sx)+0.5)/ss) / s
					uy := (float64(y) + (float64(sy)+0.5)/ss) / s
					if !inRoundedSquare(ux, uy, radius) {
						continue
					}
					c := tile
					mx, my := (ux-inset)/(1-2*inset), (uy-inset)/(1-2*inset)
					if mx >= 0 && mx <= 1 && my >= 0 && my <= 1 && mark.contains(mx, my) {
						c = white
					}
					r += float64(c.R)
					g += float64(c.G)
					b += float64(c.B)
					a++
				}
			}
			if a == 0 {
				continue
			}
			img.SetNRGBA(x, y, color.NRGBA{
				R: uint8(math.Round(r / a)), G: uint8(math.Round(g / a)), B: uint8(math.Round(b / a)),
				A: uint8(math.Round(a / (ss * ss) * 255)),
			})
		}
	}
	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

func inRoundedSquare(x, y, r float64) bool {
	if x < 0 || x > 1 || y < 0 || y > 1 {
		return false
	}
	cx := math.Min(math.Max(x, r), 1-r)
	cy := math.Min(math.Max(y, r), 1-r)
	return math.Hypot(x-cx, y-cy) <= r
}
