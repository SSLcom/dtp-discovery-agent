package transport

import (
	"context"
	"fmt"
	"time"

	"github.com/SSLcom/dtp-discovery-agent/internal/collect"
)

// Report uploads one scan, paging it under a single run id.
//
// The run id is the AGENT's own identifier for the scan, and every page carries
// it: the server folds the pages into one run, so a retried page is free rather
// than opening a second run or double-counting. Only the LAST page is `final`,
// and only the last page carries completed_sources.
func Report(ctx context.Context, client *Client, runID string, started time.Time, results []collect.Result) (*InventoryResponse, error) {
	var (
		observations []collect.Observation
		errs         []collect.Error
		completed    []string
	)
	for _, r := range results {
		observations = append(observations, r.Observations...)
		errs = append(errs, r.Errors...)
		// ONLY a collector that finished its whole sweep. A collector that hit
		// a permission error saw certificates it could not see, not
		// certificates that were removed — so naming it here would tell DTP to
		// mark those placements gone and send an operator looking for a change
		// that never happened.
		if r.Completed {
			completed = append(completed, r.Source)
		}
	}

	pages := chunk(observations, MaxObservationsPerPage)
	if len(pages) == 0 {
		// A host with no certificates still reports. Otherwise "found nothing"
		// and "never ran" look identical in the portfolio, and the whole point
		// of the run record is telling them apart.
		pages = [][]collect.Observation{{}}
	}

	var last *InventoryResponse
	for i, page := range pages {
		final := i == len(pages)-1

		req := InventoryPage{
			RunID:        runID,
			StartedAt:    started.UTC().Format(time.RFC3339),
			Final:        final,
			Observations: page,
		}
		if final {
			req.FinishedAt = time.Now().UTC().Format(time.RFC3339)
			req.CompletedSources = completed
			req.CollectorErrors = errs
		}

		resp, err := client.Inventory(ctx, req)
		if err != nil {
			return last, fmt.Errorf("uploading page %d of %d: %w", i+1, len(pages), err)
		}
		last = resp
	}
	return last, nil
}

func chunk(all []collect.Observation, size int) [][]collect.Observation {
	var out [][]collect.Observation
	for len(all) > size {
		out = append(out, all[:size])
		all = all[size:]
	}
	if len(all) > 0 {
		out = append(out, all)
	}
	return out
}
