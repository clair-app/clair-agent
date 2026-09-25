package daemon

import (
	"errors"
	"testing"

	"claircode.app/clair-agent/internal/ctl"
	"claircode.app/clair-agent/internal/update"
)

// The control surface names internal/update's outcomes as strings of its
// own; the CLI switches on them.
func TestUpdateOutcomesMatch(t *testing.T) {
	t.Parallel()

	for outcome, name := range map[update.Outcome]string{
		update.UpToDate:      ctl.OutcomeUpToDate,
		update.Available:     ctl.OutcomeAvailable,
		update.Staged:        ctl.OutcomeStaged,
		update.AlreadyStaged: ctl.OutcomeAlreadyStaged,
		update.LeftAlone:     ctl.OutcomeLeftAlone,
	} {
		if string(outcome) != name {
			t.Errorf("update.%s is %q on the control surface", outcome, name)
		}
	}
}

func TestUpdateResult(t *testing.T) {
	t.Parallel()

	res := UpdateResult("v0.1.0", update.Result{Outcome: update.Staged, Latest: "v0.2.0", Path: "/opt/clair/clair"}, nil)
	if res != (ctl.UpdateResult{Outcome: ctl.OutcomeStaged, Running: "v0.1.0", Latest: "v0.2.0", Path: "/opt/clair/clair"}) {
		t.Errorf("staged: %+v", res)
	}
	res = UpdateResult("v0.1.0", update.Result{Latest: "v0.2.0"}, errors.New("update: bad release signature"))
	if res.Outcome != ctl.OutcomeFailed || res.Error != "update: bad release signature" || res.Latest != "v0.2.0" {
		t.Errorf("failed: %+v", res)
	}
}

func TestUpdateOff(t *testing.T) {
	t.Parallel()

	d := &daemon{opts: Options{Version: "dev", UpdateOff: "this is a development build (dev)"}}
	if got := d.Update(t.Context(), ctl.UpdateRequest{}); got.Outcome != ctl.OutcomeOff || got.Note != d.opts.UpdateOff || got.Running != "dev" {
		t.Errorf("Update = %+v, want off with the reason", got)
	}
	if got := d.updateStatus(); got == nil || got.Off != d.opts.UpdateOff {
		t.Errorf("updateStatus = %+v, want off with the reason", got)
	}
}
