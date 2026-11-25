package recoverycode

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/rand"
	"strings"
	"testing"
)

func TestGenerate(t *testing.T) {
	code := Generate()
	if err := Validate(code); err != nil {
		t.Fatalf("expected generated recovery code to be valid, got error: %v", err)
	}
	if v, _ := Version(code); v != CurrentVersion {
		t.Fatalf("expected Generate to produce version %d, got %d", CurrentVersion, v)
	}
	if CurrentVersion != 2 {
		t.Fatalf("v3 must stay opt-in: CurrentVersion is %d", CurrentVersion)
	}
}

func TestGenerateVersion(t *testing.T) {
	for _, version := range []int{2, 3} {
		for i := 0; i < 10000; i++ {
			code, err := GenerateVersion(version)
			if err != nil {
				t.Fatalf("GenerateVersion(%d): %v", version, err)
			}
			got, err := Version(code)
			if err != nil || got != version {
				t.Fatalf("GenerateVersion(%d) = %q: Version() = %d, %v", version, code, got, err)
			}
			if _, err := ConvertToKey(code, ""); err != nil {
				t.Fatalf("ConvertToKey(%q): %v", code, err)
			}
			if normalized, err := Normalize(code); err != nil || normalized != code {
				t.Fatalf("Normalize(%q) = %q, %v", code, normalized, err)
			}
		}
	}
	for _, version := range []int{0, 1, 4} {
		if _, err := GenerateVersion(version); !errors.Is(err, ErrUnknownVersion) {
			t.Errorf("GenerateVersion(%d): expected ErrUnknownVersion, got %v", version, err)
		}
	}
}

func TestValidate(t *testing.T) {
	testCases := []struct {
		desc      string
		input     string
		expectErr error
	}{
		{
			desc:      "empty string",
			input:     "",
			expectErr: ErrInvalidLength,
		},
		{
			desc:      "invalid version",
			input:     "LC2Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUA",
			expectErr: ErrUnknownVersion,
		},
		{
			desc:      "v3 with 8 blocks",
			input:     "LB2Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUA",
			expectErr: ErrInvalidLength,
		},
		{
			desc:      "v3 with bad checksum",
			input:     "LBZC-MYTK-E9P3-7C7B-AHJN-KX79-22CY-WAY7-K7QA",
			expectErr: ErrInvalidChecksum,
		},
		{
			desc:      "invalid characters",
			input:     "LA2Q-48Z3-25JR-S51B-5SUS-HXHJ-RCMM-8YUA",
			expectErr: ErrInvalidCharacters,
		},
		{
			desc:      "invalid length",
			input:     "LA2Q-48Z3-25JR-SB5S-USHX-HJRC-MM8YUA",
			expectErr: ErrInvalidLength,
		},
		{
			desc:      "valid",
			input:     "LA2Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUA",
			expectErr: nil,
		},
		{
			desc:      "valid v3",
			input:     "LBZC-MYTK-E9P3-7C7B-AHJN-KX79-22CY-WAY7-K7QZ",
			expectErr: nil,
		},
	}
	for _, tt := range testCases {
		t.Run(tt.desc, func(t *testing.T) {
			err := Validate(tt.input)
			if tt.expectErr == nil && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if tt.expectErr != nil && !errors.Is(err, tt.expectErr) {
				t.Errorf("expected %v, got %v", tt.expectErr, err)
			}
		})
	}
}

func TestConvertToKey(t *testing.T) {
	testCases := []struct {
		desc     string
		input    string
		expected string
	}{
		{
			desc:     "legacy recovery code",
			input:    "R52Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUA",
			expected: "ade3fe99c608fd04484bce1ccf2889a5096f68f4b6b459e7f9ee9f0ada0a2782",
		},
		{
			desc:     "version 2 recovery code",
			input:    "LA2Q-48Z3-25JR-S5JB-5SUS-HXHJ-RCMM-8YUA",
			expected: "0e1446153d4cafb073110739608fdd76b8712221476ec198cf35e1d74d274e83",
		},
	}
	for _, tt := range testCases {
		t.Run(tt.desc, func(t *testing.T) {
			key, err := ConvertToKey(tt.input, "FFFFFFFF")
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			got := hex.EncodeToString(key.Serialize())
			if got != tt.expected {
				t.Errorf("expected %v but got %v", tt.expected, got)
			}
		})
	}
}

func TestBlockCount(t *testing.T) {
	testCases := []struct {
		prefix string
		want   int
		err    error
	}{
		{"LA2Q", 8, nil},
		{"lb", 9, nil},
		{"LBZC-MYTK", 9, nil},
		{"R52Q", 8, nil},
		{"3", 8, nil},
		{"L", 0, ErrInvalidLength},
		{"", 0, ErrInvalidLength},
		{" - ", 0, ErrInvalidLength},
		{"LC", 0, ErrUnknownVersion},
		{"L1", 0, ErrUnknownVersion},
	}
	for _, tt := range testCases {
		got, err := BlockCount(tt.prefix)
		if got != tt.want || !errors.Is(err, tt.err) && !(tt.err == nil && err == nil) {
			t.Errorf("BlockCount(%q) = %d, %v; want %d, %v", tt.prefix, got, err, tt.want, tt.err)
		}
	}
}

// --- Shared test vectors (testdata/v3_vectors.json) ---------------------------

type vectors struct {
	Validate []struct {
		Description string `json:"description"`
		Input       string `json:"input"`
		Valid       bool   `json:"valid"`
		Error       string `json:"error"`
		Version     int    `json:"version"`
		PrivateKey  string `json:"private_key"`
		Salt        string `json:"salt"`
	} `json:"validate"`
	Normalize []struct {
		Description string `json:"description"`
		Input       string `json:"input"`
		Output      string `json:"output"`
		Error       string `json:"error"`
	} `json:"normalize"`
	Locate []struct {
		Description string `json:"description"`
		Input       string `json:"input"`
		Found       bool   `json:"found"`
		Position    int    `json:"position"`
		Corrected   string `json:"corrected"`
	} `json:"locate"`
}

var errorKinds = map[string]error{
	"length":     ErrInvalidLength,
	"characters": ErrInvalidCharacters,
	"version":    ErrUnknownVersion,
	"checksum":   ErrInvalidChecksum,
}

func loadVectors(t *testing.T) *vectors {
	t.Helper()
	raw, err := ioutil.ReadFile("testdata/v3_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.Validate) == 0 || len(v.Normalize) == 0 || len(v.Locate) == 0 {
		t.Fatal("empty test vectors")
	}
	return &v
}

func TestVectorsValidate(t *testing.T) {
	for _, tt := range loadVectors(t).Validate {
		t.Run(tt.Description, func(t *testing.T) {
			version, err := Version(tt.Input)
			if !tt.Valid {
				if !errors.Is(err, errorKinds[tt.Error]) {
					t.Fatalf("Version(%q): expected %s error, got %v", tt.Input, tt.Error, err)
				}
				if _, err := ConvertToKey(tt.Input, tt.Salt); err == nil {
					t.Fatalf("ConvertToKey(%q) should fail", tt.Input)
				}
				return
			}
			if err != nil || version != tt.Version {
				t.Fatalf("Version(%q) = %d, %v; want %d", tt.Input, version, err, tt.Version)
			}
			key, err := ConvertToKey(tt.Input, tt.Salt)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(key.Serialize()); got != tt.PrivateKey {
				t.Fatalf("ConvertToKey(%q) = %s; want %s", tt.Input, got, tt.PrivateKey)
			}
		})
	}
}

func TestVectorsNormalize(t *testing.T) {
	for _, tt := range loadVectors(t).Normalize {
		t.Run(tt.Description, func(t *testing.T) {
			got, err := Normalize(tt.Input)
			if tt.Error != "" {
				if !errors.Is(err, errorKinds[tt.Error]) {
					t.Fatalf("Normalize(%q): expected %s error, got %q, %v", tt.Input, tt.Error, got, err)
				}
				return
			}
			if err != nil || got != tt.Output {
				t.Fatalf("Normalize(%q) = %q, %v; want %q", tt.Input, got, err, tt.Output)
			}
		})
	}
}

func TestVectorsLocate(t *testing.T) {
	for _, tt := range loadVectors(t).Locate {
		t.Run(tt.Description, func(t *testing.T) {
			position, corrected, ok := LocateTypo(tt.Input)
			if ok != tt.Found {
				t.Fatalf("LocateTypo(%q) ok = %v; want %v", tt.Input, ok, tt.Found)
			}
			if ok && (position != tt.Position || corrected != tt.Corrected) {
				t.Fatalf("LocateTypo(%q) = %d, %q; want %d, %q",
					tt.Input, position, corrected, tt.Position, tt.Corrected)
			}
		})
	}
}

// --- Properties ------------------------------------------------------------

func randomV3(rng *rand.Rand) []byte {
	symbols := []byte{'L', 'B'}
	for i := 0; i < randomSymbols; i++ {
		symbols = append(symbols, Alphabet[rng.Intn(len(Alphabet))])
	}
	return append(symbols, encodeChecksum(computeChecksum(symbols))...)
}

func TestChecksumDetectsAllSingleAndDoubleErrors(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	codes := 3
	if testing.Short() {
		codes = 1
	}
	for n := 0; n < codes; n++ {
		original := randomV3(rng)
		code := append([]byte(nil), original...)
		if !isValidV3(code) {
			t.Fatalf("generated code %s is invalid", format(code))
		}

		for i := 0; i < v3Symbols; i++ {
			for a := 0; a < len(Alphabet); a++ {
				if Alphabet[a] == original[i] {
					continue
				}
				code[i] = Alphabet[a]
				if Validate(format(code)) == nil {
					t.Fatalf("undetected single error at %d: %s", i, format(code))
				}

				for j := i + 1; j < v3Symbols; j++ {
					for b := 0; b < len(Alphabet); b++ {
						if Alphabet[b] == original[j] {
							continue
						}
						code[j] = Alphabet[b]
						if checksumMatches(code) && code[0] == 'L' && code[1] == 'B' {
							t.Fatalf("undetected double error at %d,%d: %s", i, j, format(code))
						}
					}
					code[j] = original[j]
				}
			}
			code[i] = original[i]
		}

		for i := 0; i < v3Symbols; i++ {
			for j := i + 1; j < v3Symbols; j++ {
				if code[i] == code[j] {
					continue
				}
				code[i], code[j] = code[j], code[i]
				if Validate(format(code)) == nil {
					t.Fatalf("undetected transposition %d,%d: %s", i, j, format(code))
				}
				code[i], code[j] = code[j], code[i]
			}
		}
	}
}

func TestLocateTypoFindsEverySingleError(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	for n := 0; n < 5; n++ {
		original := randomV3(rng)
		want := format(original)
		code := append([]byte(nil), original...)
		for i := 0; i < v3Symbols; i++ {
			for a := 0; a < len(Alphabet); a++ {
				if Alphabet[a] == original[i] {
					continue
				}
				code[i] = Alphabet[a]
				position, corrected, ok := LocateTypo(format(code))
				if !ok || position != i || corrected != want {
					t.Fatalf("LocateTypo(%s) = %d, %q, %v; want %d, %q",
						format(code), position, corrected, ok, i, want)
				}
			}
			// A symbol outside the alphabet at the same position.
			code[i] = 'O'
			if position, corrected, ok := LocateTypo(string(code)); !ok || position != i || corrected != want {
				t.Fatalf("LocateTypo(%s) with invalid char = %d, %q, %v", code, position, corrected, ok)
			}
			code[i] = original[i]
		}
		if _, _, ok := LocateTypo(want); ok {
			t.Fatalf("LocateTypo(%s) found a typo in a valid code", want)
		}
	}
}

func TestLocateTypoDoubleErrorSuggestionsAreOneSymbolAway(t *testing.T) {
	// With 2 errors, LocateTypo may suggest a *different* valid code (that's
	// why suggestions are hints only), but any suggestion must be valid and
	// exactly one symbol away from the input.
	rng := rand.New(rand.NewSource(3))
	suggestions, trials := 0, 10000
	for n := 0; n < trials; n++ {
		code := randomV3(rng)
		i, j := rng.Intn(v3Symbols), rng.Intn(v3Symbols)
		for i == j {
			j = rng.Intn(v3Symbols)
		}
		code[i] = otherSymbol(rng, code[i])
		code[j] = otherSymbol(rng, code[j])
		input := format(code)
		position, corrected, ok := LocateTypo(input)
		if !ok {
			continue
		}
		suggestions++
		if Validate(corrected) != nil {
			t.Fatalf("LocateTypo(%s) suggested invalid code %s", input, corrected)
		}
		if diff := symbolDiff(input, corrected); diff != 1 {
			t.Fatalf("LocateTypo(%s) suggestion %s differs in %d symbols", input, corrected, diff)
		}
		if stripDashes(corrected)[position] == code[position] {
			t.Fatalf("LocateTypo(%s) reported unchanged position %d", input, position)
		}
	}
	t.Logf("double errors with a (wrong) suggestion: %d / %d", suggestions, trials)
}

func otherSymbol(rng *rand.Rand, c byte) byte {
	for {
		d := Alphabet[rng.Intn(len(Alphabet))]
		if d != c {
			return d
		}
	}
}

func symbolDiff(a, b string) int {
	x, y := stripDashes(a), stripDashes(b)
	diff := 0
	for i := range x {
		if x[i] != y[i] {
			diff++
		}
	}
	return diff
}

func TestChecksumCoversFullRange(t *testing.T) {
	rng := rand.New(rand.NewSource(4))
	var seen1, seen2 [checksumModulus]bool
	for n := 0; n < 100000; n++ {
		s1, s2 := computeChecksum(randomV3(rng))
		seen1[s1], seen2[s2] = true, true
	}
	for v := 0; v < checksumModulus; v++ {
		if !seen1[v] || !seen2[v] {
			t.Fatalf("checksum value %d never produced (S1 %v, S2 %v)", v, seen1[v], seen2[v])
		}
	}
}

// TestRandomInputs is a fuzz-style test (go.mod targets Go 1.14, which has no
// native fuzzing): random inputs must never panic, and Normalize must be
// idempotent.
func TestRandomInputs(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	pool := Alphabet + strings.ToLower(Alphabet) + "--  \t01IOGé"
	for n := 0; n < 50000; n++ {
		var sb strings.Builder
		length := rng.Intn(50)
		if n%2 == 0 {
			sb.WriteString("LB")
		}
		runes := []rune(pool)
		for i := 0; i < length; i++ {
			sb.WriteRune(runes[rng.Intn(len(runes))])
		}
		input := sb.String()

		_, _ = Version(input)
		_, _, _ = LocateTypo(input)
		_, _ = BlockCount(input)
		if normalized, err := Normalize(input); err == nil {
			again, err := Normalize(normalized)
			if err != nil || again != normalized {
				t.Fatalf("Normalize not idempotent for %q: %q then %q, %v", input, normalized, again, err)
			}
		}
	}
}
