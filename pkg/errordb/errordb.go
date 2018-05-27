package errordb

import (
	"crypto/sha1"
	"fmt"
	"io"
	"regexp"

	"a4.io/blobstash/pkg/rangedb"
	"github.com/golang/snappy"
	"github.com/vmihailenco/msgpack"
)

var (
	PythonErrorRegex = regexp.MustCompile(`(?s)Traceback \(most recent call last\)\:\n.*`)
)

var (
	Python = "py"
	Golang = "go"
)

type Occurrence struct {
	T      int64  `msgpack:"t" json:"time"`
	LogRef string `msgpack:"r" json:"log_ref"`
}

type AppError struct {
	StackTrace string `msgpack:"st" json:"stack_trace"`
	Lang       string `msgpack:"l" json:"language"`

	FirstSeen int64 `msgpack:"fs" json:"first_seen"`
	LastSeen  int64 `msgpack:"ls" json:"last_seen"`

	Status string `msgpack:"s" json:"status"`

	Occurrences []*Occurrence `msgpack:"o" json:"occurrences"`

	ID string `msgpack:"-" json:"id"`
}

func errorID(ae *AppError) string {
	return fmt.Sprintf("%x", sha1.Sum([]byte(ae.StackTrace)))
}

type ErrorDB struct {
	rdb *rangedb.RangeDB
}

func New(path string) (*ErrorDB, error) {
	rdb, err := rangedb.New(path)
	if err != nil {
		return nil, err
	}
	return &ErrorDB{
		rdb: rdb,
	}, nil
}

func (db *ErrorDB) Close() error {
	return db.rdb.Close()
}

func (db *ErrorDB) Get(eid string) (*AppError, error) {
	v, err := db.rdb.Get([]byte(eid))
	if err != nil {
		return nil, err
	}

	if v == nil {
		return nil, nil
	}

	data, err := snappy.Decode(nil, v)
	if err != nil {
		return nil, err
	}

	ae := &AppError{ID: eid}
	if err := msgpack.Unmarshal(data, ae); err != nil {
		return nil, err
	}

	return ae, nil
}

func (db *ErrorDB) ProcessLogMessage(logRef string, ts int64, message string) error {
	tb := PythonErrorRegex.FindString(message)
	if tb == "" {
		return nil
	}
	eid := fmt.Sprintf("%x", sha1.Sum([]byte(tb)))
	cae, err := db.Get(eid)
	if err != nil {
		return err
	}
	if cae == nil {
		cae = &AppError{
			Lang:        Python,
			StackTrace:  tb,
			ID:          eid,
			FirstSeen:   ts,
			Occurrences: []*Occurrence{},
			Status:      "open",
		}
	}
	cae.LastSeen = ts
	cae.Occurrences = append(cae.Occurrences, &Occurrence{T: ts, LogRef: logRef})
	switch cae.Status {
	case "resolved":
		cae.Status = "re-opened"
	}

	data, err := msgpack.Marshal(cae)
	if err != nil {
		return err
	}

	if err := db.rdb.Set([]byte(eid), snappy.Encode(nil, data)); err != nil {
		return err
	}

	return nil
}

func (db *ErrorDB) List(cursor string, limit int) ([]*AppError, string, error) {
	out := []*AppError{}

	bcursor := []byte{'\xff'}
	if cursor != "" {
		bcursor = []byte(cursor)
	}
	c := db.rdb.Range([]byte(""), bcursor, true)
	k, v, err := c.Next()
	if err == io.EOF {
		return out, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	var skipFirst bool
	for ; err == nil && (limit <= 0 || len(out) < limit); k, v, err = c.Next() {
		if cursor != "" && !skipFirst {
			skipFirst = true
			continue
		}
		ae := &AppError{
			ID: string(k),
		}
		data, err := snappy.Decode(nil, v)
		if err != nil {
			return nil, "", err
		}
		if err := msgpack.Unmarshal(data, ae); err != nil {
			return nil, "", err
		}

		out = append(out, ae)
	}
	if len(out) > 0 {
		cursor = out[len(out)-1].ID
	}
	return out, cursor, nil
}
