package netann

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/lightningnetwork/lnd/input"
	"github.com/lightningnetwork/lnd/lnwallet"
)

// NodeSigner is an implementation of the MessageSigner interface backed by the
// identity private key of running lnd node.
type NodeSigner struct {
	privKey *btcec.PrivateKey
}

// NewNodeSigner creates a new instance of the NodeSigner backed by the target
// private key.
func NewNodeSigner(key *btcec.PrivateKey) *NodeSigner {
	priv := &btcec.PrivateKey{}
	priv.Curve = btcec.S256()
	priv.PublicKey.X = key.X
	priv.PublicKey.Y = key.Y
	priv.D = key.D
	return &NodeSigner{
		privKey: priv,
	}
}

// SignMessage signs a double-sha256 digest of the passed msg under the
// resident node's private key. If the target public key is _not_ the node's
// private key, then an error will be returned.
func (n *NodeSigner) SignMessage(pubKey *btcec.PublicKey,
	msg []byte) (input.Signature, error) {

	// If this isn't our identity public key, then we'll exit early with an
	// error as we can't sign with this key.
	if !pubKey.IsEqual(n.privKey.PubKey()) {
		return nil, fmt.Errorf("unknown public key")
	}

	// Otherwise, we'll sign the dsha256 of the target message.
	digest := chainhash.DoubleHashB(msg)
	sig, err := n.privKey.Sign(digest)
	if err != nil {
		return nil, fmt.Errorf("can't sign the message: %v", err)
	}

	return sig, nil
}

// SignCompact signs a double-sha256 digest of the msg parameter under the
// resident node's private key. The returned signature is a pubkey-recoverable
// signature.
func (n *NodeSigner) SignCompact(msg []byte) ([]byte, error) {
	// We'll sign the dsha256 of the target message.
	digest := chainhash.DoubleHashB(msg)

	return n.SignDigestCompact(digest)
}

// SignDigestCompact signs the provided message digest under the resident
// node's private key. The returned signature is a pubkey-recoverable signature.
func (n *NodeSigner) SignDigestCompact(hash []byte) ([]byte, error) {

	// Should the signature reference a compressed public key or not.
	isCompressedKey := true

	// btcec.SignCompact returns a pubkey-recoverable signature
	sig, err := btcec.SignCompact(
		btcec.S256(), n.privKey, hash, isCompressedKey,
	)
	if err != nil {
		return nil, fmt.Errorf("can't sign the hash: %v", err)
	}

	return sig, nil
}

// A compile time check to ensure that NodeSigner implements the MessageSigner
// interface.
var _ lnwallet.MessageSigner = (*NodeSigner)(nil)
