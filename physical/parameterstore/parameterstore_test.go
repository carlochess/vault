package paramstore

import (
	"testing"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/helper/logging"
	"github.com/hashicorp/vault/physical"
)

func TestDynamoDBBackend(t *testing.T) {
	logger := logging.NewVaultLogger(log.Debug)

	b, err := NewParamStoreBackend(map[string]string{
		"access_key": "",
		"secret_key": "",
	}, logger)
	
	if err != nil {
		t.Fatalf("err: %s", err)
	}

	physical.ExerciseBackend(t, b)
	physical.ExerciseBackend_ListPrefix(t, b)
}
