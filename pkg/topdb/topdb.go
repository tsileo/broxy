package topdb

import (
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"a4.io/blobstash/pkg/rangedb"
)

type Interval int

const (
	All Interval = iota
	Year
	Month
	Day
)

var Intervals = []Interval{All, Day, Month, Year}

var iToFmt = map[Interval]string{
	Year:  "2006",
	Month: "2006-01",
	Day:   "2006-01-02",
}

func fmtTime(i Interval, t time.Time) string {
	if i == All {
		return ""
	}
	return t.Format(iToFmt[i])
}

func cacheKeyPrefix(interval Interval, t time.Time) string {
	return fmt.Sprintf("%d:%s", interval, fmtTime(interval, t))
}

type TopDB struct {
	rdb *rangedb.RangeDB
}

func New(path string) (*TopDB, error) {
	rdb, err := rangedb.New(path)
	if err != nil {
		return nil, err
	}
	return &TopDB{
		rdb: rdb,
	}, nil
}

func (db *TopDB) Close() error {
	return db.rdb.Close()
}

func hash(key string) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(key)))
}

func decodeVal(val []byte) (uint64, string) {
	return binary.BigEndian.Uint64(val[0:8]), string(val[8:])
}

func (db *TopDB) Get(i Interval, t time.Time, top, key string) (uint64, error) {
	var cval uint64
	k := []byte(cacheKeyPrefix(i, t) + fmt.Sprintf(":%s:%s", top, hash(key)))
	cdata, err := db.rdb.Get(k)
	if err != nil {
		return cval, err
	}
	if cdata != nil {
		cval, _ = decodeVal(cdata)
	}
	return cval, nil
}
func (db *TopDB) Incr(i Interval, t time.Time, top, key string, value uint64) error {
	k := []byte(cacheKeyPrefix(i, t) + fmt.Sprintf(":%s:%s", top, hash(key)))
	cdata, err := db.rdb.Get(k)
	if err != nil {
		return err
	}
	var cval uint64
	if cdata != nil {
		cval, _ = decodeVal(cdata)
	}
	v := make([]byte, len(key)+8)
	binary.BigEndian.PutUint64(v[:], cval+value)
	copy(v[8:], []byte(key))
	return db.rdb.Set(k, v)
}

type TopEntry struct {
	Key   string
	Value uint64
}

func (db *TopDB) GetTops(i Interval, t time.Time, top string) ([]*TopEntry, error) {
	out := []*TopEntry{}
	prefix := []byte(cacheKeyPrefix(i, t) + fmt.Sprintf(":%s:", top))
	c := db.rdb.Range(prefix, append(prefix, '\xff'), false)
	_, v, err := c.Next()
	if err == io.EOF {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	for ; err == nil; _, v, err = c.Next() {
		cval, key := decodeVal(v)
		out = append(out, &TopEntry{key, cval})
	}
	return out, nil
}
