//go:build !windows

package collect

// IIS runs on Windows and nowhere else, so on every other platform this
// contributes nothing and says nothing. It is not a limitation worth reporting:
// an absent IIS on a Linux host is exactly as interesting as an absent nginx.
func iisObservations() ([]Observation, []Error, bool) { return nil, nil, true }
