package channeldb

import (
	"github.com/lightningnetwork/lnd/channeldb/kvdb"
)

var (
	// metaBucket stores all the meta information concerning the state of
	// the database.
	metaBucket = []byte("metadata")

	// dbVersionKey is a boltdb key and it's used for storing/retrieving
	// current database version.
	dbVersionKey = []byte("dbp")
)

// Meta structure holds the database meta information.
type Meta struct {
	// DbVersionNumber is the current schema version of the database.
	DbVersionNumber uint32
}

// FetchMeta fetches the meta data from boltdb and returns filled meta
// structure.
func (d *DB) FetchMeta(tx kvdb.ReadTx) (*Meta, error) {
	meta := &Meta{}

	err := kvdb.View(d, func(tx kvdb.ReadTx) error {
		return fetchMeta(meta, tx)
	})
	if err != nil {
		return nil, err
	}

	return meta, nil
}

// fetchMeta is an internal helper function used in order to allow callers to
// re-use a database transaction. See the publicly exported FetchMeta method
// for more information.
func fetchMeta(meta *Meta, tx kvdb.ReadTx) error {
	metaBucket := tx.ReadBucket(metaBucket)
	if metaBucket == nil {
		return ErrMetaNotFound
	}

	data := metaBucket.Get(dbVersionKey)
	if data == nil {
		meta.DbVersionNumber = getLatestDBVersion(dbVersions)
	} else {
		meta.DbVersionNumber = byteOrder.Uint32(data)
	}

	return nil
}

// PutMeta writes the passed instance of the database met-data struct to disk.
func (d *DB) PutMeta(meta *Meta) error {
	return kvdb.Update(d, func(tx kvdb.RwTx) error {
		return putMeta(meta, tx)
	})
}

// putMeta is an internal helper function used in order to allow callers to
// re-use a database transaction. See the publicly exported PutMeta method for
// more information.
func putMeta(meta *Meta, tx kvdb.RwTx) error {
	metaBucket, err := tx.CreateTopLevelBucket(metaBucket)
	if err != nil {
		return err
	}

	return putDbVersion(metaBucket, meta)
}

func putDbVersion(metaBucket kvdb.RwBucket, meta *Meta) error {
	scratch := make([]byte, 4)
	byteOrder.PutUint32(scratch, meta.DbVersionNumber)
	return metaBucket.Put(dbVersionKey, scratch)
}
