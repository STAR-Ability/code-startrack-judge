package migrate

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadIdentitiesAndChecksums(t *testing.T) {
	files := fstest.MapFS{"README.md": {Data: []byte("policy")}, "000001_schema.up.sql": {Data: []byte("BEGIN;\nSELECT 1;\nCOMMIT;\n")}, "000002_indexes.up.sql": {Data: []byte("BEGIN;\nSELECT 2;\nCOMMIT;\n")}}
	migrations, err := Load(files)
	if err != nil || len(migrations) != 2 || len(migrations[0].SHA256) != 64 {
		t.Fatalf("load: %v, %v", migrations, err)
	}
	original := migrations[0].SHA256
	files["000001_schema.up.sql"].Data = []byte("BEGIN;\nSELECT 1;\nCOMMIT;")
	migrations, err = Load(files)
	if err != nil || migrations[0].SHA256 == original {
		t.Fatal("checksum must include unchanged original bytes")
	}
}

func TestLoadRejectsUnsafeHistory(t *testing.T) {
	for _, names := range [][]string{
		{"000000_schema.up.sql"}, {"000002_schema.up.sql"},
		{"000001_schema.up.sql", "000001_other.up.sql"},
		{"000001_schema.up.sql", "000003_other.up.sql"},
		{"000001_schema.down.sql"}, {"1_schema.up.sql"},
		{"000001_Schema.up.sql"}, {"arbitrary.sql"},
	} {
		t.Run(strings.Join(names, ","), func(t *testing.T) {
			files := fstest.MapFS{}
			for _, name := range names {
				files[name] = &fstest.MapFile{Data: []byte("BEGIN;\nSELECT 1;\nCOMMIT;")}
			}
			if _, err := Load(files); err == nil {
				t.Fatal("unsafe history accepted")
			}
		})
	}
}

func TestDatabaseErrorDoesNotLeakDriverDiagnostics(t *testing.T) {
	secret := "postgres://private:credential@database/judge secret SQL"
	err := dbError("connect", &fakeDriverError{message: secret})
	if strings.Contains(err.Error(), secret) || !strings.Contains(err.Error(), "08001") {
		t.Fatalf("unsafe diagnostic: %s", err)
	}
}

type fakeDriverError struct{ message string }

func (e *fakeDriverError) Error() string    { return e.message }
func (e *fakeDriverError) SQLState() string { return "08001" }
