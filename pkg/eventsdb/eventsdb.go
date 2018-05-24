package eventsdb

import (
	"encoding/hex"
	"io"
	"time"

	"a4.io/blobstash/pkg/docstore/id"
	"a4.io/blobstash/pkg/rangedb"
	"github.com/vmihailenco/msgpack"
)

type EventsDB struct {
	rdb *rangedb.RangeDB
}

func New(path string) (*EventsDB, error) {
	rdb, err := rangedb.New(path)
	if err != nil {
		return nil, err
	}
	return &EventsDB{
		rdb: rdb,
	}, nil
}

func (db *EventsDB) Close() error {
	return db.rdb.Close()
}

type Event struct {
	Type    string `msgpack:"t"`
	Message string `msgpack:"m"`
	ID      *id.ID `msgpack:"-"`
}

func (db *EventsDB) Add(event *Event) error {
	eid, err := id.New(time.Now().UTC().UnixNano())
	if err != nil {
		return err
	}
	data, err := msgpack.Marshal(event)
	if err != nil {
		return err
	}
	if err := db.rdb.Set(eid.Raw(), data); err != nil {
		return err
	}
	return nil
}

func (db *EventsDB) List(cursor string, limit int) ([]*Event, string, error) {
	out := []*Event{}

	bcursor := []byte{'\xff'}
	if cursor != "" {
		cid, err := id.FromHex(cursor)
		if err != nil {
			return nil, "", err
		}
		bcursor = cid.Raw()
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
		eid, err := id.FromHex(hex.EncodeToString(k))
		if err != nil {
			return nil, "", err
		}
		event := &Event{
			ID: eid,
		}
		if err := msgpack.Unmarshal(v, event); err != nil {
			return nil, "", err
		}

		out = append(out, event)
	}
	if len(out) > 0 {
		cursor = out[len(out)-1].ID.String()
	}
	return out, cursor, nil
}
