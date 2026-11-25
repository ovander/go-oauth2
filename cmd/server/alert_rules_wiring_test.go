// Package main — ALERT_RULES_MODE wiring (#258): the evaluation is scheduled
// under observe and enforce only.
package main

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/config"
)

func TestStartAlertRules(t *testing.T) {
	for _, mode := range []string{"off", ""} {
		if stop := startAlertRules(&config.Config{AlertRulesMode: mode, AlertRulesInterval: time.Hour}, nil, nil, nil, nil, nil, nil); stop != nil {
			stop()
			t.Errorf("mode %q: the evaluation was scheduled", mode)
		}
	}
	for _, mode := range []string{"observe", "enforce"} {
		stop := startAlertRules(&config.Config{AlertRulesMode: mode, AlertRulesInterval: time.Hour}, nil, nil, nil, nil, nil, nil)
		if stop == nil {
			t.Fatalf("mode %q: the evaluation was not scheduled", mode)
		}
		stop()
	}
}
