package secrets_test

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/jrandolf/secrets"
	"github.com/jrandolf/secrets/env"
	"github.com/jrandolf/secrets/file"
	"github.com/jrandolf/secrets/literal"
)

func Example() {
	// For testing, use literal + env providers.
	os.Setenv("EXAMPLE_API_KEY", "sk-test-123")
	defer os.Unsetenv("EXAMPLE_API_KEY")

	r := secrets.NewResolver(
		secrets.WithDefault(literal.New(map[string][]byte{
			"prod/db": []byte(`{"host":"db.example.com","port":5432,"password":"s3cret"}`),
		})),
		secrets.WithProvider("env", env.New()),
		secrets.WithProvider("file", file.New()),
	)
	defer r.Close()

	type Config struct {
		DBHost string `secret:"prod/db#host"`
		DBPort int    `secret:"prod/db#port"`
		DBPass string `secret:"prod/db#password"`
		APIKey string `secret:"env://EXAMPLE_API_KEY"`
		Debug  bool   `secret:"debug,optional"`
	}

	var cfg Config
	if err := r.Resolve(context.Background(), &cfg); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("host=%s port=%d key=%s debug=%v\n", cfg.DBHost, cfg.DBPort, cfg.APIKey, cfg.Debug)
	// Output: host=db.example.com port=5432 key=sk-test-123 debug=false
}
