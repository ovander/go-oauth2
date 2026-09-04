package service

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// A2: user attributes are bounded at write time, because a client's claim
// mapping can project them into every token it is issued.
func TestValidateUserAttributes(t *testing.T) {
	if err := validateUserAttributes(nil); err != nil {
		t.Errorf("nil attributes: %v", err)
	}
	if err := validateUserAttributes(model.JSONMap{}); err != nil {
		t.Errorf("empty attributes: %v", err)
	}
	if err := validateUserAttributes(model.JSONMap{"tier": "gold", "seats": 3}); err != nil {
		t.Errorf("ordinary attributes: %v", err)
	}

	tooMany := model.JSONMap{}
	for i := 0; i <= MaxUserAttributes; i++ {
		tooMany[fmt.Sprintf("attr-%d", i)] = i
	}
	if err := validateUserAttributes(tooMany); !errors.Is(err, ErrInvalidUserAttributes) {
		t.Errorf("too many attributes: err = %v, want ErrInvalidUserAttributes", err)
	}

	if err := validateUserAttributes(model.JSONMap{"": "x"}); !errors.Is(err, ErrInvalidUserAttributes) {
		t.Errorf("empty name: err = %v, want ErrInvalidUserAttributes", err)
	}

	longName := strings.Repeat("n", MaxUserAttributeName+1)
	if err := validateUserAttributes(model.JSONMap{longName: "x"}); !errors.Is(err, ErrInvalidUserAttributes) {
		t.Errorf("over-long name: err = %v, want ErrInvalidUserAttributes", err)
	}

	oversized := model.JSONMap{"blob": strings.Repeat("x", MaxUserAttributeSize)}
	if err := validateUserAttributes(oversized); !errors.Is(err, ErrInvalidUserAttributes) {
		t.Errorf("oversized set: err = %v, want ErrInvalidUserAttributes", err)
	}

	// A value JSON cannot represent is refused rather than stored and failing
	// later at issuance.
	if err := validateUserAttributes(model.JSONMap{"ch": make(chan int)}); !errors.Is(err, ErrInvalidUserAttributes) {
		t.Errorf("unserializable value: err = %v, want ErrInvalidUserAttributes", err)
	}
}
