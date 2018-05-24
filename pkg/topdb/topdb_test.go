package topdb

import (
	"testing"
	"time"
)

func TestTopDBTopsBasic(t *testing.T) {
	db, err := New("ok")
	if err != nil {
		t.Fatal(err)
	}
	defer db.rdb.Destroy()

	ti := time.Now().UTC()
	if err := db.Incr(All, ti, "t1", "v1", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Incr(All, ti, "t1", "v2", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Incr(All, ti, "t1", "v2", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Incr(All, ti, "t1", "v3", 3); err != nil {
		t.Fatal(err)
	}
	tops, err := db.GetTops(All, ti, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tops) != 3 {
		t.Fatalf("failed")
	}

}

func TestTopDBTops(t *testing.T) {
	db, err := New("ok")
	if err != nil {
		t.Fatal(err)
	}
	defer db.rdb.Destroy()

	ti := time.Now().UTC()
	if err := db.Incr(Day, ti, "t1", "v1", 100); err != nil {
		t.Fatal(err)
	}

	if err := db.Incr(All, ti, "t1", "v1", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Incr(All, ti, "t1", "v2", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Incr(All, ti, "t1", "v2", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.Incr(All, ti, "t1", "v3", 3); err != nil {
		t.Fatal(err)
	}
	if err := db.Incr(All, ti, "t2", "v1", 1); err != nil {
		t.Fatal(err)
	}

	tops, err := db.GetTops(All, ti, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tops) != 3 {
		t.Fatalf("failed")
	}
	tops, err = db.GetTops(Day, ti, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tops) != 1 {
		t.Fatalf("failed")
	}
}

func TestTopDBIncrAndGet(t *testing.T) {
	db, err := New("ok")
	if err != nil {
		t.Fatal(err)
	}
	defer db.rdb.Destroy()

	ti := time.Now().UTC()
	zval, err := db.Get(All, ti, "t1", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if zval != 0 {
		t.Logf("expected 0")
	}

	if err := db.Incr(All, ti, "t1", "v1", 1); err != nil {
		t.Fatal(err)
	}
	val, err := db.Get(All, ti, "t1", "v1")
	if err != nil {
		t.Fatal(err)
	}

	if val != 1 {
		t.Errorf("expected 1, got %d", val)
	}
	if err := db.Incr(All, ti, "t1", "v1", 1); err != nil {
		t.Fatal(err)
	}
	val, err = db.Get(All, ti, "t1", "v1")
	if err != nil {
		t.Fatal(err)
	}

	if val != 2 {
		t.Errorf("expected 2, got %d", val)
	}
}
