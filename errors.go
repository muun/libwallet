package libwallet

const (
	ErrUnknown               = 1
	ErrInvalidURI            = 2
	ErrNetwork               = 3
	ErrInvalidPrivateKey     = 4
	ErrInvalidDerivationPath = 5
	ErrInvalidInvoice        = 6

	// ErrInvalidRecoveryCode means the input isn't a well-formed recovery
	// code (wrong length, characters or version).
	ErrInvalidRecoveryCode = 7
	// ErrInvalidRecoveryCodeChecksum means the input is a well-formed v3+
	// recovery code whose checksum doesn't match: most likely a typo.
	ErrInvalidRecoveryCodeChecksum = 8
)

func ErrorCode(err error) int64 {
	type coder interface {
		Code() int64
	}
	switch e := err.(type) {
	case coder:
		return e.Code()
	default:
		return ErrUnknown
	}
}
