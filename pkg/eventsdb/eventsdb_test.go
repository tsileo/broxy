package eventsdb

import (
	"fmt"
	"testing"
)

func TestEventsDBEmpty(t *testing.T) {
	db, err := New("ok")
	if err != nil {
		t.Fatal(err)
	}
	defer db.rdb.Destroy()
	out, _, err := db.List("", -1)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 0 {
		t.Errorf("DB should be empty")
	}
}

func TestEventsDB(t *testing.T) {
	db, err := New("ok")
	if err != nil {
		t.Fatal(err)
	}
	defer db.rdb.Destroy()

	for i := 0; i < 100; i++ {
		t.Logf("%d\n", i)
		if err := db.Add(&Event{Message: fmt.Sprintf("lol-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}

	t.Logf("db=%+v\n", db)

	total := 0
	out, cursor, err := db.List("", 60)
	if err != nil {
		t.Fatal(err)
	}
	total += len(out)
	t.Logf("out[%d]=%q\n", len(out), out)
	out, cursor, err = db.List(cursor, 60)
	if err != nil {
		t.Fatal(err)
	}
	total += len(out)
	t.Logf("out[%d]=%q\n", len(out), out)

	if total != 100 {
		t.Errorf("failed to retrieve the event, got %d, expected 100", total)
	}
}
