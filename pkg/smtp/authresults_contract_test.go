package smtp

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"

	"migadu/mizu/pkg/config"
	"migadu/mizu/pkg/validation"

	"github.com/emersion/go-msgauth/authres"
)

// authFormatVectors is mailqueuer's model of the X-Mizu-Authentication-Results
// line (spec/Mailqueuer/Auth.lean), generated there by `make spec-vectors`.
// mailqueuer's TestConformance_AuthParse checks its parser reads these lines
// back; this test checks Mizu writes exactly them. Both repos sit side by
// side under services/.
const authFormatVectors = "../../../mailqueuer/spec/vectors/auth_format.json"

func TestAuthResultsHeader_MatchesMailqueuerContract(t *testing.T) {
	data, err := os.ReadFile(authFormatVectors)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("%s not found (mailqueuer not checked out beside mizu)", authFormatVectors)
	}
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			SPF, DKIM, DMARC, ARC, Line string
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, c := range vectors.Cases {
		// Mizu reports dkim from the DMARC check: without one, both are
		// "none"; the model's other combinations can't occur here.
		if (c.DKIM == "none") != (c.DMARC == "none") {
			continue
		}
		spf := &validation.SPFResult{Result: authres.SPFResult{Value: authres.ResultValue(c.SPF)}}
		var dmarc *validation.DMARCResult
		if c.DMARC != "none" {
			dmarc = &validation.DMARCResult{Pass: c.DMARC == "pass", DKIMAligned: c.DKIM == "pass"}
		}
		var arc *validation.ARCResult
		if c.ARC != "none" {
			arc = &validation.ARCResult{Instance: 1, Pass: c.ARC == "pass"}
		}
		got := buildMizuHeaders("t1", spf, dmarc, arc, false, config.HeaderToggles{AuthResults: true})
		if got != c.Line {
			t.Errorf("spf=%s dkim=%s dmarc=%s arc=%s: Mizu writes %q, mailqueuer's contract says %q",
				c.SPF, c.DKIM, c.DMARC, c.ARC, got, c.Line)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no reachable cases in the vectors")
	}
}
