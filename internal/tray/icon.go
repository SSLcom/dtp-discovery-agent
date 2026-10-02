package tray

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"math"
)

// Icon draws the notification-area icon for a health, as a PNG of size×size
// pixels — the form Windows accepts directly as an icon image since Vista.
//
// DRAWN, NOT SHIPPED AS FILES. The size Windows wants depends on the display's
// scaling (16 px at 100%, 20 at 125%, 24 at 150%, 32 at 200%), and drawing at
// the asked-for size is sharper than shipping four bitmaps and stretching the
// nearest one. It also keeps the release free of binary assets nobody reviews.
//
// SHAPE, NOT ONLY COLOUR. A tick, an exclamation mark, a bar and a ring, so the
// icon is legible to someone who cannot tell the green from the amber — about
// one man in twelve.
func Icon(h Health, size int) []byte {
	fill, mark := palette(h)
	img := image.NewNRGBA(image.Rect(0, 0, size, size))

	const ss = 4 // supersamples per axis, for anti-aliased edges
	s := float64(size)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			var discCover, markCover float64
			for sy := 0; sy < ss; sy++ {
				for sx := 0; sx < ss; sx++ {
					// Unit coordinates: the icon spans [-1, 1] on both axes.
					px := (float64(x)+(float64(sx)+0.5)/ss)/s*2 - 1
					py := (float64(y)+(float64(sy)+0.5)/ss)/s*2 - 1
					in, onMark := shade(h, px, py, s)
					if in {
						discCover++
					}
					if onMark {
						markCover++
					}
				}
			}
			n := float64(ss * ss)
			discCover /= n
			markCover /= n
			if discCover == 0 {
				continue
			}
			c := mix(fill, mark, markCover/discCover)
			c.A = uint8(math.Round(discCover * 255))
			img.SetNRGBA(x, y, c)
		}
	}

	var buf bytes.Buffer
	_ = png.Encode(&buf, img)
	return buf.Bytes()
}

// shade reports whether a point is inside the icon, and whether it is on the
// glyph drawn over it.
func shade(h Health, x, y, size float64) (in, onMark bool) {
	r := math.Hypot(x, y)
	if r > 0.94 {
		return false, false
	}
	// Strokes are a fixed fraction of the icon, with a floor of roughly one and
	// a half pixels so they survive at 16 px.
	w := math.Max(0.16, 3.0/size)

	switch h {
	case Good: // a tick
		return true, segment(x, y, -0.42, 0.02, -0.12, 0.34) < w || segment(x, y, -0.12, 0.34, 0.46, -0.30) < w
	case Attention: // an exclamation mark
		return true, segment(x, y, 0, -0.58, 0, -0.06) < w*0.9 || math.Hypot(x, y-0.50) < w
	case Problem: // a no-entry bar
		return true, segment(x, y, -0.48, 0, 0.48, 0) < w*1.1
	default: // a ring: the agent's state is not known
		return r > 0.94-2*w, false
	}
}

// segment is the distance from a point to the line segment a–b.
func segment(px, py, ax, ay, bx, by float64) float64 {
	dx, dy := bx-ax, by-ay
	t := ((px-ax)*dx + (py-ay)*dy) / (dx*dx + dy*dy)
	t = math.Max(0, math.Min(1, t))
	return math.Hypot(px-(ax+t*dx), py-(ay+t*dy))
}

func palette(h Health) (fill, mark color.NRGBA) {
	white := color.NRGBA{255, 255, 255, 255}
	switch h {
	case Good:
		return color.NRGBA{0x16, 0x8a, 0x4a, 255}, white
	case Attention:
		return color.NRGBA{0xd9, 0x77, 0x06, 255}, white
	case Problem:
		return color.NRGBA{0xc8, 0x22, 0x22, 255}, white
	default:
		return color.NRGBA{0x6b, 0x72, 0x80, 255}, white
	}
}

func mix(a, b color.NRGBA, t float64) color.NRGBA {
	t = math.Max(0, math.Min(1, t))
	l := func(x, y uint8) uint8 { return uint8(math.Round(float64(x)*(1-t) + float64(y)*t)) }
	return color.NRGBA{l(a.R, b.R), l(a.G, b.G), l(a.B, b.B), 255}
}
