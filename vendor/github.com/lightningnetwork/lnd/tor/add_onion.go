package tor

import (
	"errors"
	"fmt"
	"io/ioutil"
	"os"
)

var (
	// ErrNoPrivateKey is an error returned by the OnionStore.PrivateKey
	// method when a private key hasn't yet been stored.
	ErrNoPrivateKey = errors.New("private key not found")
)

// OnionType denotes the type of the onion service.
type OnionType int

const (
	// V2 denotes that the onion service is V2.
	V2 OnionType = iota

	// V3 denotes that the onion service is V3.
	V3
)

// OnionStore is a store containing information about a particular onion
// service.
type OnionStore interface {
	// StorePrivateKey stores the private key according to the
	// implementation of the OnionStore interface.
	StorePrivateKey(OnionType, []byte) error

	// PrivateKey retrieves a stored private key. If it is not found, then
	// ErrNoPrivateKey should be returned.
	PrivateKey(OnionType) ([]byte, error)

	// DeletePrivateKey securely removes the private key from the store.
	DeletePrivateKey(OnionType) error
}

// OnionFile is a file-based implementation of the OnionStore interface that
// stores an onion service's private key.
type OnionFile struct {
	privateKeyPath string
	privateKeyPerm os.FileMode
}

// A compile-time constraint to ensure OnionFile satisfies the OnionStore
// interface.
var _ OnionStore = (*OnionFile)(nil)

// NewOnionFile creates a file-based implementation of the OnionStore interface
// to store an onion service's private key.
func NewOnionFile(privateKeyPath string, privateKeyPerm os.FileMode) *OnionFile {
	return &OnionFile{
		privateKeyPath: privateKeyPath,
		privateKeyPerm: privateKeyPerm,
	}
}

// StorePrivateKey stores the private key at its expected path.
func (f *OnionFile) StorePrivateKey(_ OnionType, privateKey []byte) error {
	return ioutil.WriteFile(f.privateKeyPath, privateKey, f.privateKeyPerm)
}

// PrivateKey retrieves the private key from its expected path. If the file does
// not exist, then ErrNoPrivateKey is returned.
func (f *OnionFile) PrivateKey(_ OnionType) ([]byte, error) {
	if _, err := os.Stat(f.privateKeyPath); os.IsNotExist(err) {
		return nil, ErrNoPrivateKey
	}
	return ioutil.ReadFile(f.privateKeyPath)
}

// DeletePrivateKey removes the file containing the private key.
func (f *OnionFile) DeletePrivateKey(_ OnionType) error {
	return os.Remove(f.privateKeyPath)
}

// AddOnionConfig houses all of the required parameters in order to successfully
// create a new onion service or restore an existing one.
type AddOnionConfig struct {
	// Type denotes the type of the onion service that should be created.
	Type OnionType

	// VirtualPort is the externally reachable port of the onion address.
	VirtualPort int

	// TargetPorts is the set of ports that the service will be listening on
	// locally. The Tor server will use choose a random port from this set
	// to forward the traffic from the virtual port.
	//
	// NOTE: If nil/empty, the virtual port will be used as the only target
	// port.
	TargetPorts []int

	// Store is responsible for storing all onion service related
	// information.
	//
	// NOTE: If not specified, then nothing will be stored, making onion
	// services unrecoverable after shutdown.
	Store OnionStore
}

// AddOnion creates an onion service and returns its onion address. Once
// created, the new onion service will remain active until the connection
// between the controller and the Tor server is closed.
func (c *Controller) AddOnion(cfg AddOnionConfig) (*OnionAddr, error) {
	// Before sending the request to create an onion service to the Tor
	// server, we'll make sure that it supports V3 onion services if that
	// was the type requested.
	if cfg.Type == V3 {
		if err := supportsV3(c.version); err != nil {
			return nil, err
		}
	}

	// We'll start off by checking if the store contains an existing private
	// key. If it does not, then we should request the server to create a
	// new onion service and return its private key. Otherwise, we'll
	// request the server to recreate the onion server from our private key.
	var keyParam string
	switch cfg.Type {
	case V2:
		keyParam = "NEW:RSA1024"
	case V3:
		keyParam = "NEW:ED25519-V3"
	}

	if cfg.Store != nil {
		privateKey, err := cfg.Store.PrivateKey(cfg.Type)
		switch err {
		// Proceed to request a new onion service.
		case ErrNoPrivateKey:

		// Recover the onion service with the private key found.
		case nil:
			keyParam = string(privateKey)

		default:
			return nil, err
		}
	}

	// Now, we'll create a mapping from the virtual port to each target
	// port. If no target ports were specified, we'll use the virtual port
	// to provide a one-to-one mapping.
	var portParam string

	// Helper function which appends the correct Port param depending on
	// whether the user chose to use a custom target IP address or not.
	pushPortParam := func(targetPort int) {
		if c.targetIPAddress == "" {
			portParam += fmt.Sprintf("Port=%d,%d ", cfg.VirtualPort,
				targetPort)
		} else {
			portParam += fmt.Sprintf("Port=%d,%s:%d ", cfg.VirtualPort,
				c.targetIPAddress, targetPort)
		}
	}

	if len(cfg.TargetPorts) == 0 {
		pushPortParam(cfg.VirtualPort)
	} else {
		for _, targetPort := range cfg.TargetPorts {
			pushPortParam(targetPort)
		}
	}

	// Send the command to create the onion service to the Tor server and
	// await its response.
	cmd := fmt.Sprintf("ADD_ONION %s %s", keyParam, portParam)
	_, reply, err := c.sendCommand(cmd)
	if err != nil {
		return nil, err
	}

	// If successful, the reply from the server should be of the following
	// format, depending on whether a private key has been requested:
	//
	//	C: ADD_ONION RSA1024:[Blob Redacted] Port=80,8080
	//	S: 250-ServiceID=testonion1234567
	//	S: 250 OK
	//
	//	C: ADD_ONION NEW:RSA1024 Port=80,8080
	//	S: 250-ServiceID=testonion1234567
	//	S: 250-PrivateKey=RSA1024:[Blob Redacted]
	//	S: 250 OK
	//
	// We're interested in retrieving the service ID, which is the public
	// name of the service, and the private key if requested.
	replyParams := parseTorReply(reply)
	serviceID, ok := replyParams["ServiceID"]
	if !ok {
		return nil, errors.New("service id not found in reply")
	}

	// If a new onion service was created and an onion store was provided,
	// we'll store its private key to disk in the event that it needs to be
	// recreated later on.
	if privateKey, ok := replyParams["PrivateKey"]; cfg.Store != nil && ok {
		err := cfg.Store.StorePrivateKey(cfg.Type, []byte(privateKey))
		if err != nil {
			return nil, fmt.Errorf("unable to write private key "+
				"to file: %v", err)
		}
	}

	// Finally, we'll return the onion address composed of the service ID,
	// along with the onion suffix, and the port this onion service can be
	// reached at externally.
	return &OnionAddr{
		OnionService: serviceID + ".onion",
		Port:         cfg.VirtualPort,
	}, nil
}
