package lnwire

import (
	"io"
	"math"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

// QueryChannelRange is a message sent by a node in order to query the
// receiving node of the set of open channel they know of with short channel
// ID's after the specified block height, capped at the number of blocks beyond
// that block height. This will be used by nodes upon initial connect to
// synchronize their views of the network.
type QueryChannelRange struct {
	// ChainHash denotes the target chain that we're trying to synchronize
	// channel graph state for.
	ChainHash chainhash.Hash

	// FirstBlockHeight is the first block in the query range. The
	// responder should send all new short channel IDs from this block
	// until this block plus the specified number of blocks.
	FirstBlockHeight uint32

	// NumBlocks is the number of blocks beyond the first block that short
	// channel ID's should be sent for.
	NumBlocks uint32
}

// NewQueryChannelRange creates a new empty QueryChannelRange message.
func NewQueryChannelRange() *QueryChannelRange {
	return &QueryChannelRange{}
}

// A compile time check to ensure QueryChannelRange implements the
// lnwire.Message interface.
var _ Message = (*QueryChannelRange)(nil)

// Decode deserializes a serialized QueryChannelRange message stored in the
// passed io.Reader observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (q *QueryChannelRange) Decode(r io.Reader, pver uint32) error {
	return ReadElements(r,
		q.ChainHash[:],
		&q.FirstBlockHeight,
		&q.NumBlocks,
	)
}

// Encode serializes the target QueryChannelRange into the passed io.Writer
// observing the protocol version specified.
//
// This is part of the lnwire.Message interface.
func (q *QueryChannelRange) Encode(w io.Writer, pver uint32) error {
	return WriteElements(w,
		q.ChainHash[:],
		q.FirstBlockHeight,
		q.NumBlocks,
	)
}

// MsgType returns the integer uniquely identifying this message type on the
// wire.
//
// This is part of the lnwire.Message interface.
func (q *QueryChannelRange) MsgType() MessageType {
	return MsgQueryChannelRange
}

// MaxPayloadLength returns the maximum allowed payload size for a
// QueryChannelRange complete message observing the specified protocol version.
//
// This is part of the lnwire.Message interface.
func (q *QueryChannelRange) MaxPayloadLength(uint32) uint32 {
	// 32 + 4 + 4
	return 40
}

// LastBlockHeight returns the last block height covered by the range of a
// QueryChannelRange message.
func (q *QueryChannelRange) LastBlockHeight() uint32 {
	// Handle overflows by casting to uint64.
	lastBlockHeight := uint64(q.FirstBlockHeight) + uint64(q.NumBlocks) - 1
	if lastBlockHeight > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(lastBlockHeight)
}
