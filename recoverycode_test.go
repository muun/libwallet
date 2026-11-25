package libwallet

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"reflect"
	"testing"
)

func TestRecoveryCodeToKey(t *testing.T) {
	type args struct {
		code string
		salt string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "boop",
			args: args{
				code: "3V4N-R9EC-V3TQ-NRB3-Q7NY-9HXP-CSDC-B5BC",
				salt: "63f701fda4fc0b0c",
			},
			want:    "0220af974bdfdf4274d21c061bbf21e67d3e2687f5b43073b4e9aac5bae53a3602",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RecoveryCodeToKey(tt.args.code, tt.args.salt)
			if (err != nil) != tt.wantErr {
				t.Errorf("RecoveryCodeToKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.PubKeyHex(), tt.want) {
				t.Errorf("RecoveryCodeToKey() got = %v, want %v", got.PubKeyHex(), tt.want)
			}
		})
	}
}

func TestRecoveryCodeVectors(t *testing.T) {
	raw, err := ioutil.ReadFile("recoverycode/testdata/v3_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Validate []struct {
			Description string `json:"description"`
			Input       string `json:"input"`
			Valid       bool   `json:"valid"`
			Error       string `json:"error"`
			Version     int    `json:"version"`
			PrivateKey  string `json:"private_key"`
			Salt        string `json:"salt"`
		} `json:"validate"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}

	for _, tt := range vectors.Validate {
		t.Run(tt.Description, func(t *testing.T) {
			err := ValidateRecoveryCode(tt.Input)
			if !tt.Valid {
				want := int64(ErrInvalidRecoveryCode)
				if tt.Error == "checksum" {
					want = ErrInvalidRecoveryCodeChecksum
				}
				if err == nil || ErrorCode(err) != want {
					t.Fatalf("ValidateRecoveryCode(%q) = %v (code %d); want code %d",
						tt.Input, err, ErrorCode(err), want)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateRecoveryCode(%q): %v", tt.Input, err)
			}
			version, err := GetRecoveryCodeVersion(tt.Input)
			if err != nil || version != tt.Version {
				t.Fatalf("GetRecoveryCodeVersion(%q) = %d, %v", tt.Input, version, err)
			}
			key, err := RecoveryCodeToKey(tt.Input, tt.Salt)
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(key.key.Serialize()); got != tt.PrivateKey {
				t.Fatalf("RecoveryCodeToKey(%q) = %s; want %s", tt.Input, got, tt.PrivateKey)
			}
		})
	}
}

func TestGenerateRecoveryCodeWithVersion(t *testing.T) {
	if v, _ := GetRecoveryCodeVersion(GenerateRecoveryCode()); v != 2 {
		t.Fatalf("GenerateRecoveryCode must keep producing v2 codes, got v%d", v)
	}
	code, err := GenerateRecoveryCodeWithVersion(3)
	if err != nil {
		t.Fatal(err)
	}
	if v, err := GetRecoveryCodeVersion(code); err != nil || v != 3 {
		t.Fatalf("GetRecoveryCodeVersion(%q) = %d, %v", code, v, err)
	}
	if _, err := GenerateRecoveryCodeWithVersion(4); ErrorCode(err) != ErrInvalidRecoveryCode {
		t.Fatalf("GenerateRecoveryCodeWithVersion(4) = %v", err)
	}
	if RecoveryCodeLatestVersion != 3 {
		t.Fatalf("RecoveryCodeLatestVersion = %d", RecoveryCodeLatestVersion)
	}
}

func TestNormalizeRecoveryCode(t *testing.T) {
	const want = "LBZC-MYTK-E9P3-7C7B-AHJN-KX79-22CY-WAY7-K7QZ"
	got, err := NormalizeRecoveryCode("  lbzc mytk e9p3 7c7b ahjn kx79 22cy way7 k7qz ")
	if err != nil || got != want {
		t.Fatalf("NormalizeRecoveryCode = %q, %v; want %q", got, err, want)
	}
	if _, err := NormalizeRecoveryCode("LBZC"); ErrorCode(err) != ErrInvalidRecoveryCode {
		t.Fatalf("NormalizeRecoveryCode(short) = %v", err)
	}
}

func TestLocateRecoveryCodeTypo(t *testing.T) {
	const valid = "LBZC-MYTK-E9P3-7C7B-AHJN-KX79-22CY-WAY7-K7QZ"
	if typo := LocateRecoveryCodeTypo(valid); typo != nil {
		t.Fatalf("found typo in valid code: %+v", typo)
	}
	// Block 5, character 2: H -> X
	typo := LocateRecoveryCodeTypo("LBZC-MYTK-E9P3-7C7B-AXJN-KX79-22CY-WAY7-K7QZ")
	want := &RecoveryCodeTypo{Block: 5, Index: 2, Position: 17, Suggested: valid}
	if !reflect.DeepEqual(typo, want) {
		t.Fatalf("LocateRecoveryCodeTypo = %+v; want %+v", typo, want)
	}
}

func TestRecoveryCodeBlockCount(t *testing.T) {
	for prefix, want := range map[string]int{"LA2Q": 8, "LBZC": 9, "R52Q": 8} {
		if got, err := RecoveryCodeBlockCount(prefix); err != nil || got != want {
			t.Errorf("RecoveryCodeBlockCount(%q) = %d, %v; want %d", prefix, got, err, want)
		}
	}
	if _, err := RecoveryCodeBlockCount("LC"); ErrorCode(err) != ErrInvalidRecoveryCode {
		t.Errorf("RecoveryCodeBlockCount(LC) = %v", err)
	}
}
