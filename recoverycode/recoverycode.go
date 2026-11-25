package recoverycode

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/crypto/scrypt"

	"github.com/btcsuite/btcd/btcec"
)

const (
	kdfKey                   = "muun:rc"
	kdfIterations            = 512
	kdfBlockSize             = 8
	kdfParallelizationFactor = 1
	kdfOutputLength          = 32
)

// CurrentVersion is the version Generate produces. It stays at 2: version 3
// codes are opt-in through GenerateVersion(3).
const CurrentVersion = 2

// LatestVersion is the highest recovery code version this package can
// parse, validate and convert to a key.
const LatestVersion = 3

// Alphabet contains all upper-case characters except for numbers/letters that
// look alike.
const Alphabet = "ABCDEFHJKLMNPQRSTUVWXYZ2345789"

// AlphabetLegacy constains the letters that pre version 2 recovery codes can
// contain.
const AlphabetLegacy = "ABCDEFHJKMNPQRSTUVWXYZ2345789"

const (
	blockSize       = 4
	randomSymbols   = 30
	bodySymbols     = 32 // 'L' + version + random symbols
	v3Symbols       = 36 // body + checksum block
	checksumModulus = 887
	legacyBlocks    = 8
	v3Blocks        = 9
)

var (
	// ErrInvalidLength is returned when a recovery code has the wrong number
	// of characters for its version.
	ErrInvalidLength = errors.New("invalid recovery code length")
	// ErrInvalidCharacters is returned when a recovery code contains a
	// character outside its alphabet or a misplaced separator.
	ErrInvalidCharacters = errors.New("invalid recovery code characters")
	// ErrUnknownVersion is returned when a recovery code's version character
	// doesn't correspond to a supported version.
	ErrUnknownVersion = errors.New("unrecognized recovery code version")
	// ErrInvalidChecksum is returned when a well-formed version 3+ recovery
	// code doesn't match its checksum, which usually means a typo.
	ErrInvalidChecksum = errors.New("invalid recovery code checksum")
)

// Generate creates a new random recovery code of version CurrentVersion
// using a cryptographically secure random number generator.
func Generate() string {
	code, err := GenerateVersion(CurrentVersion)
	if err != nil {
		panic(err) // CurrentVersion is always generatable
	}
	return code
}

// GenerateVersion creates a new random recovery code of the given version
// (2 or 3) using a cryptographically secure random number generator.
func GenerateVersion(version int) (string, error) {
	if version < 2 || version > LatestVersion {
		return "", fmt.Errorf("%w: cannot generate version %d", ErrUnknownVersion, version)
	}

	symbols := make([]byte, 0, v3Symbols)
	symbols = append(symbols, 'L', versionChar(version))
	for i := 0; i < randomSymbols; i++ {
		symbols = append(symbols, randChar(Alphabet))
	}
	if version >= 3 {
		symbols = append(symbols, encodeChecksum(computeChecksum(symbols))...)
	}

	return format(symbols), nil
}

// randChar returns a random character from the given string
//
// The algorithm was inspired by BSD arc4random_uniform function to avoid
// modulo bias and ensure a uniform distribution
// http://cvsweb.openbsd.org/cgi-bin/cvsweb/~checkout~/src/lib/libc/crypt/arc4random_uniform.c
func randChar(chars string) byte {
	clen := len(chars)
	// Reject bytes below 256 % clen so that the remaining range is an exact
	// multiple of clen. (arc4random_uniform computes this as -n % n on
	// unsigned ints; with Go's signed ints that expression is always 0.)
	min := 256 % clen
	for {
		var b [1]byte
		_, err := rand.Read(b[:])
		if err != nil {
			panic("could not read enough random bytes for recovery code")
		}
		r := int(b[0])
		if r < min {
			continue
		}
		return chars[r%clen]
	}
}

// ConvertToKey generates a private key using the recovery code as a seed.
//
// The salt parameter is only used for version 1 codes. It will be ignored
// for version 2+ codes.
func ConvertToKey(code, salt string) (*btcec.PrivateKey, error) {
	version, err := Version(code)
	if err != nil {
		return nil, err
	}

	var input []byte

	switch version {
	case 1:
		saltBytes, err := hex.DecodeString(salt)
		if err != nil {
			return nil, fmt.Errorf("failed to decode salt: %w", err)
		}

		input, err = scrypt.Key(
			[]byte(code),
			saltBytes,
			kdfIterations,
			kdfBlockSize,
			kdfParallelizationFactor,
			kdfOutputLength,
		)
		if err != nil {
			return nil, err
		}
	case 2, 3:
		mac := hmac.New(sha256.New, []byte(kdfKey))
		mac.Write([]byte(code))
		input = mac.Sum(nil)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}

	// 2nd return value is the pub key which we don't need right now
	priv, _ := btcec.PrivKeyFromBytes(btcec.S256(), input)
	return priv, nil
}

// Validate returns an error if the recovery code is not valid or nil otherwise.
//
// Validation is strict: the code must be in canonical form (upper-case, with
// dashes). Use Normalize on user input first. For version 3+ codes this also
// verifies the checksum, returning an error wrapping ErrInvalidChecksum on a
// mismatch.
func Validate(code string) error {
	_, err := Version(code)
	return err
}

// Version returns the version that this recovery code corresponds to.
//
// Errors wrap one of ErrInvalidLength, ErrInvalidCharacters,
// ErrUnknownVersion or ErrInvalidChecksum.
func Version(code string) (int, error) {
	if len(code) >= 2 && code[0] == 'L' { // version 2+ codes always start with L
		version, err := versionFromChar(rune(code[1]))
		if err != nil {
			return 0, err
		}
		blocks := blockCountFor(version)
		if len(code) != formattedLength(blocks) {
			return 0, fmt.Errorf("%w %v", ErrInvalidLength, len(code))
		}
		if !validateFormat(code, Alphabet) {
			return 0, ErrInvalidCharacters
		}
		if version >= 3 && !checksumMatches(stripDashes(code)) {
			return 0, ErrInvalidChecksum
		}
		return version, nil
	}

	if len(code) != formattedLength(legacyBlocks) {
		return 0, fmt.Errorf("%w %v", ErrInvalidLength, len(code))
	}
	if !validateFormat(code, AlphabetLegacy) {
		return 0, ErrInvalidCharacters
	}
	return 1, nil
}

// Normalize converts user input into the canonical recovery code form
// expected by Validate and ConvertToKey: it upper-cases the input, removes
// whitespace and dashes, checks the symbol count for the detected version
// and re-inserts a dash every 4 symbols.
//
// Normalize doesn't check the alphabet or the checksum; call Validate on
// its output.
func Normalize(code string) (string, error) {
	symbols := stripSeparators(code)

	want := legacyBlocks * blockSize
	if len(symbols) >= 2 && symbols[0] == 'L' {
		version, err := versionFromChar(symbols[1])
		if err != nil {
			return "", err
		}
		want = blockCountFor(version) * blockSize
	}
	if len(symbols) != want {
		return "", fmt.Errorf("%w: %d symbols", ErrInvalidLength, len(symbols))
	}

	return formatRunes(symbols), nil
}

// LocateTypo finds a single-symbol error in a version 3 recovery code.
//
// It returns the 0-based symbol position of the error (dashes excluded) and
// the corrected code in canonical form. ok is false if the input is already
// valid, isn't a 36-symbol code, or isn't exactly one symbol away from a
// unique valid version 3 code.
//
// The result is only a suggestion: input with 2+ errors can be one symbol
// away from a different valid code, so callers must not apply it silently.
func LocateTypo(code string) (position int, corrected string, ok bool) {
	runes := stripSeparators(code)
	if len(runes) != v3Symbols {
		return 0, "", false
	}

	// Copy into bytes, marking symbols outside the alphabet with '?'.
	symbols := make([]byte, v3Symbols)
	var bad []int
	for i, r := range runes {
		if r > unicode.MaxASCII || strings.IndexByte(Alphabet, byte(r)) == -1 {
			symbols[i] = '?'
			bad = append(bad, i)
			continue
		}
		symbols[i] = byte(r)
	}

	var candidates []int
	switch len(bad) {
	case 0:
		if isValidV3(symbols) {
			return 0, "", false
		}
		for i := 0; i < v3Symbols; i++ {
			candidates = append(candidates, i)
		}
	case 1:
		candidates = bad
	default:
		return 0, "", false
	}

	found := -1
	var fix []byte
	for _, i := range candidates {
		original := symbols[i]
		for j := 0; j < len(Alphabet); j++ {
			c := Alphabet[j]
			if c == original {
				continue
			}
			symbols[i] = c
			if isValidV3(symbols) {
				if found != -1 {
					return 0, "", false // ambiguous; can't happen with distance 3
				}
				found = i
				fix = append([]byte(nil), symbols...)
			}
		}
		symbols[i] = original
	}

	if found == -1 {
		return 0, "", false
	}
	return found, format(fix), true
}

// BlockCount returns how many 4-symbol blocks a recovery code has, based on
// its first symbols: 8 for version 1 and 2 codes, 9 for version 3 codes.
// Input UIs can use it to size themselves once the first block is entered.
func BlockCount(prefix string) (int, error) {
	symbols := stripSeparators(prefix)
	if len(symbols) == 0 {
		return 0, fmt.Errorf("%w: empty prefix", ErrInvalidLength)
	}
	if symbols[0] != 'L' {
		return legacyBlocks, nil
	}
	if len(symbols) < 2 {
		return 0, fmt.Errorf("%w: need at least 2 symbols", ErrInvalidLength)
	}
	version, err := versionFromChar(symbols[1])
	if err != nil {
		return 0, err
	}
	return blockCountFor(version), nil
}

// versionChar returns the character that encodes a version 2+ code version.
// The first character of the alphabet corresponds to version 2.
func versionChar(version int) byte {
	return Alphabet[version-2]
}

func versionFromChar(c rune) (int, error) {
	if c > unicode.MaxASCII {
		return 0, fmt.Errorf("%w: %q", ErrUnknownVersion, c)
	}
	idx := strings.IndexByte(Alphabet, byte(c))
	if idx == -1 {
		return 0, fmt.Errorf("%w: %q", ErrUnknownVersion, c)
	}
	version := idx + 2
	if version > LatestVersion {
		return 0, fmt.Errorf("%w: %d", ErrUnknownVersion, version)
	}
	return version, nil
}

func blockCountFor(version int) int {
	if version >= 3 {
		return v3Blocks
	}
	return legacyBlocks
}

func formattedLength(blocks int) int {
	return blocks*(blockSize+1) - 1
}

// validateFormat checks that every 5th character is a dash and that every
// other character belongs to the alphabet. The caller checks the length.
func validateFormat(code, alphabet string) bool {
	for i := 0; i < len(code); i++ {
		if i%(blockSize+1) == blockSize {
			if code[i] != '-' {
				return false
			}
			continue
		}
		if strings.IndexByte(alphabet, code[i]) == -1 {
			return false
		}
	}
	return true
}

// computeChecksum returns the two weighted sums mod 887 over the first 32
// symbols, which must all belong to Alphabet.
func computeChecksum(symbols []byte) (s1, s2 int) {
	for i := 0; i < bodySymbols; i++ {
		v := strings.IndexByte(Alphabet, symbols[i])
		w := i + 1
		s1 = (s1 + w*v) % checksumModulus
		s2 = (s2 + w*w*v) % checksumModulus
	}
	return s1, s2
}

func encodeChecksum(s1, s2 int) []byte {
	n := len(Alphabet)
	return []byte{Alphabet[s1/n], Alphabet[s1%n], Alphabet[s2/n], Alphabet[s2%n]}
}

func decodeChecksumPair(a, b byte) (int, bool) {
	hi := strings.IndexByte(Alphabet, a)
	lo := strings.IndexByte(Alphabet, b)
	if hi == -1 || lo == -1 {
		return 0, false
	}
	v := hi*len(Alphabet) + lo
	if v >= checksumModulus {
		return 0, false
	}
	return v, true
}

// checksumMatches reports whether block 9 of a 36-symbol code (no dashes)
// matches its body. All symbols must belong to Alphabet.
func checksumMatches(symbols []byte) bool {
	if len(symbols) != v3Symbols {
		return false
	}
	s1, s2 := computeChecksum(symbols)
	d1, ok1 := decodeChecksumPair(symbols[32], symbols[33])
	d2, ok2 := decodeChecksumPair(symbols[34], symbols[35])
	return ok1 && ok2 && d1 == s1 && d2 == s2
}

// isValidV3 reports whether 36 symbols (no dashes) form a valid version 3
// code.
func isValidV3(symbols []byte) bool {
	if symbols[0] != 'L' || symbols[1] != versionChar(3) {
		return false
	}
	for _, c := range symbols {
		if strings.IndexByte(Alphabet, c) == -1 {
			return false
		}
	}
	return checksumMatches(symbols)
}

func stripDashes(code string) []byte {
	symbols := make([]byte, 0, len(code))
	for i := 0; i < len(code); i++ {
		if code[i] != '-' {
			symbols = append(symbols, code[i])
		}
	}
	return symbols
}

// stripSeparators upper-cases the input and removes dashes and whitespace.
func stripSeparators(code string) []rune {
	var symbols []rune
	for _, r := range strings.ToUpper(code) {
		if r == '-' || unicode.IsSpace(r) {
			continue
		}
		symbols = append(symbols, r)
	}
	return symbols
}

func format(symbols []byte) string {
	var sb strings.Builder
	for i, c := range symbols {
		if i > 0 && i%blockSize == 0 {
			sb.WriteByte('-')
		}
		sb.WriteByte(c)
	}
	return sb.String()
}

func formatRunes(symbols []rune) string {
	var sb strings.Builder
	for i, r := range symbols {
		if i > 0 && i%blockSize == 0 {
			sb.WriteByte('-')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}
