package libwallet

import (
	stderrors "errors"

	"github.com/muun/libwallet/errors"
	"github.com/muun/libwallet/recoverycode"
)

// RecoveryCodeAlphabet contains all upper-case characters except for
// numbers/letters that look alike.
const RecoveryCodeAlphabet = recoverycode.Alphabet

// RecoveryCodeLatestVersion is the highest recovery code version this
// library can parse, validate and convert to a key.
const RecoveryCodeLatestVersion = recoverycode.LatestVersion

// RecoveryCodeTypo describes a single-symbol typo found in a recovery code.
type RecoveryCodeTypo struct {
	// Block is the 1-based block (group of 4 symbols) holding the typo.
	Block int
	// Index is the 1-based position of the typo within its block.
	Index int
	// Position is the 0-based symbol position of the typo, dashes excluded.
	Position int
	// Suggested is the corrected recovery code in canonical form. It must
	// only be shown as a suggestion, never applied without user confirmation.
	Suggested string
}

// GenerateRecoveryCode generates a new random recovery code using a
// cryptographically secure random number generator.
//
// It produces version 2 codes. Use GenerateRecoveryCodeWithVersion(3) to
// opt in to version 3 codes, which carry a checksum.
func GenerateRecoveryCode() string {
	return recoverycode.Generate()
}

// GenerateRecoveryCodeWithVersion generates a new random recovery code of
// the given version (2 or 3) using a cryptographically secure random number
// generator.
func GenerateRecoveryCodeWithVersion(version int) (string, error) {
	code, err := recoverycode.GenerateVersion(version)
	if err != nil {
		return "", wrapRecoveryCodeError(err)
	}
	return code, nil
}

// RecoveryCodeToKey generates a challenge private key using the
// recovery code as a seed.
//
// The salt parameter is only used for version 1 codes. It will be ignored
// for version 2+ codes.
func RecoveryCodeToKey(code, salt string) (*ChallengePrivateKey, error) {
	privKey, err := recoverycode.ConvertToKey(code, salt)
	if err != nil {
		return nil, wrapRecoveryCodeError(err)
	}
	return &ChallengePrivateKey{key: privKey}, nil
}

// ValidateRecoveryCode returns an error if the recovery code is not valid
// or nil otherwise.
//
// The error code (see ErrorCode) is ErrInvalidRecoveryCodeChecksum for a
// v3 code with a typo, and ErrInvalidRecoveryCode for any other invalid
// input. The code must be canonical; see NormalizeRecoveryCode.
func ValidateRecoveryCode(code string) error {
	return wrapRecoveryCodeError(recoverycode.Validate(code))
}

// GetRecoveryCodeVersion returns the version for the recovery code given.
// If no version can be recognized, it returns an error.
func GetRecoveryCodeVersion(code string) (int, error) {
	version, err := recoverycode.Version(code)
	if err != nil {
		return 0, wrapRecoveryCodeError(err)
	}
	return version, nil
}

// NormalizeRecoveryCode converts user input (any case, with or without
// dashes or whitespace) into the canonical form expected by
// ValidateRecoveryCode and RecoveryCodeToKey.
func NormalizeRecoveryCode(code string) (string, error) {
	normalized, err := recoverycode.Normalize(code)
	if err != nil {
		return "", wrapRecoveryCodeError(err)
	}
	return normalized, nil
}

// LocateRecoveryCodeTypo looks for a single-symbol typo in a version 3
// recovery code. It returns nil if the code is valid or the typo can't be
// located (for example, because there's more than one).
func LocateRecoveryCodeTypo(code string) *RecoveryCodeTypo {
	position, suggested, ok := recoverycode.LocateTypo(code)
	if !ok {
		return nil
	}
	return &RecoveryCodeTypo{
		Block:     position/4 + 1,
		Index:     position%4 + 1,
		Position:  position,
		Suggested: suggested,
	}
}

// RecoveryCodeBlockCount returns the number of 4-symbol blocks a recovery
// code has (8 or 9) given at least its first 2 symbols.
func RecoveryCodeBlockCount(prefix string) (int, error) {
	count, err := recoverycode.BlockCount(prefix)
	if err != nil {
		return 0, wrapRecoveryCodeError(err)
	}
	return count, nil
}

func wrapRecoveryCodeError(err error) error {
	switch {
	case err == nil:
		return nil
	case stderrors.Is(err, recoverycode.ErrInvalidChecksum):
		return errors.Errorf(ErrInvalidRecoveryCodeChecksum, "%v", err)
	case stderrors.Is(err, recoverycode.ErrInvalidLength),
		stderrors.Is(err, recoverycode.ErrInvalidCharacters),
		stderrors.Is(err, recoverycode.ErrUnknownVersion):
		return errors.Errorf(ErrInvalidRecoveryCode, "%v", err)
	default:
		return err
	}
}
