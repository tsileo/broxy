package errordb

import (
	"testing"
	"time"
)

const logLine = `ERROR:root:lol
Traceback (most recent call last):
  File "<ipython-input-10-439952f488ea>", line 2, in <module>
    1/0
ZeroDivisionError: division by zero`

func TestErrorDB(t *testing.T) {
	edb, err := New("ok")
	if err != nil {
		t.Fatal(err)
	}
	defer edb.rdb.Destroy()

	ferr, err := edb.Get("lol")
	if ferr != nil || err != nil {
		t.Fatal(err)
	}

	ti := time.Now().Unix()
	if err := edb.ProcessLogMessage("lref", ti, logLine); err != nil {
		t.Fatal(err)
	}
	if err := edb.ProcessLogMessage("lref2", ti+1, logLine); err != nil {
		t.Fatal(err)
	}

	aes, _, err := edb.List("", -1)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("errors=%q\n", aes)

	if len(aes) != 1 {
		t.Errorf("expected 1 error, got %d", len(aes))
	}

	ae := aes[0]
	if len(ae.Occurrences) != 2 {
		t.Errorf("expected 2 error occurences, got %d", len(ae.Occurrences))

	}
	if ae.LastSeen != ti+1 || ae.FirstSeen != ti {
		t.Errorf("invalid first/last seen")
	}
}
