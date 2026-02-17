# secrets

A Go library for reading secrets from multiple providers using struct tags.

```go
type Config struct {
    DBHost string              `secret:"awssm://prod/db#host"`
    DBPort int                 `secret:"awssm://prod/db#port"`
    DBPass string              `secret:"awssm://prod/db#password"`
    APIKey string              `secret:"env://API_KEY"`
    Debug  bool                `secret:"debug,optional"`
    Cert   []byte              `secret:"file:///etc/tls/cert.pem"`
    EncKey secrets.Versioned[[]byte] `secret:"awssm://prod/enc-key"`
}
```

Declare secrets as struct fields, resolve them from any combination of providers, and watch for changes at runtime.

## Install

```
go get github.com/jrandolf/secrets
```

## Usage

```go
r := secrets.NewResolver(
    secrets.WithDefault(awssm.New(awssm.WithRegion("us-west-2"))),
    secrets.WithProvider("env", env.New()),
    secrets.WithProvider("file", file.New()),
)
defer r.Close()

var cfg Config
if err := r.Resolve(ctx, &cfg); err != nil {
    log.Fatal(err)
}
```

Cloud providers return `(*Provider, error)` from `New()`:

```go
sm, err := awssm.New(awssm.WithRegion("us-west-2"))
if err != nil {
    log.Fatal(err)
}
r := secrets.NewResolver(secrets.WithDefault(sm))
```

## Tag format

```
secret:"[scheme://]key[#fragment][,option...]"
```

| Tag                                 | Meaning                                 |
| ----------------------------------- | --------------------------------------- |
| `secret:"db-pass"`                  | Bare key, uses default provider         |
| `secret:"awssm://prod/db#password"` | AWS Secrets Manager, extract JSON field |
| `secret:"env://API_KEY"`            | Environment variable                    |
| `secret:"file:///etc/tls/cert.pem"` | File contents                           |
| `secret:"key,optional"`             | Zero value if missing                   |
| `secret:"key,version=previous"`     | Specific version                        |

Bare keys (no scheme) route to the default provider. Keys with a scheme route to the provider registered for that scheme. The `#fragment` extracts a field from JSON-encoded secrets. Nested fragments like `#db.host` are supported.

## Supported field types

`string`, `[]byte`, `bool`, `int`/`int8`-`int64`, `uint`/`uint8`-`uint64`, `float32`, `float64`, `time.Duration`, pointer variants (`*string`, etc.), `encoding.TextUnmarshaler` implementations, `Versioned[T]`, and nested/embedded structs.

## Providers

| Package               | Scheme        | Backend                 | Versioned | Default config                                                       |
| --------------------- | ------------- | ----------------------- | --------- | -------------------------------------------------------------------- |
| `secrets/awssm`       | `awssm`       | AWS Secrets Manager     | Yes       | Standard AWS credential chain                                        |
| `secrets/awsps`       | `awsps`       | AWS SSM Parameter Store | No        | Standard AWS credential chain, `decrypt: true`                       |
| `secrets/gcpsm`       | `gcpsm`       | GCP Secret Manager      | Yes       | Application Default Credentials, project from `GOOGLE_CLOUD_PROJECT` |
| `secrets/azkv`        | `azkv`        | Azure Key Vault         | Yes       | `DefaultAzureCredential`, requires `WithVaultURL`                    |
| `secrets/vault`       | `vault`       | HashiCorp Vault KV v2   | Yes       | `VAULT_ADDR`/`VAULT_TOKEN` from env, mount `"secret"`                |
| `secrets/onepassword` | `onepassword` | 1Password CLI           | No        | `op` CLI auth                                                        |
| `secrets/env`         | `env`         | Environment variables   | No        |                                                                      |
| `secrets/file`        | `file`        | Filesystem              | No        |                                                                      |
| `secrets/literal`     | `literal`     | In-memory map           | Yes       | For testing                                                          |

Each provider accepts a `WithClient` option to inject a custom or pre-configured client implementation.

## Key rotation

Use `Versioned[T]` to fetch both current and previous values. The provider must implement `VersionedProvider`.

```go
type Config struct {
    EncKey secrets.Versioned[[]byte] `secret:"awssm://prod/enc-key"`
}

// cfg.EncKey.Current  — active key
// cfg.EncKey.Previous — previous key for re-encryption
```

Use `version=` to fetch a specific version:

```go
type Config struct {
    OldKey string `secret:"key,version=previous"`
}
```

## Watching for changes

```go
w, err := r.Watch(ctx, &cfg, secrets.WatchInterval(5*time.Minute))
if err != nil {
    log.Fatal(err)
}
defer w.Stop()

go func() {
    for event := range w.Changes() {
        log.Printf("secret %s changed", event.Field)
        w.RLock()
        // read cfg safely
        w.RUnlock()
    }
}()
```

The watcher polls at the configured interval (default 1 minute), updates only secret-tagged fields under a write lock, and emits `ChangeEvent` values on the channel. Use `w.RLock()`/`w.RUnlock()` when reading the struct from other goroutines.

## Validation

```go
if err := r.Validate(&cfg); err != nil {
    log.Fatal(err) // bad tags, unknown schemes, unsupported types
}
```

Checks tag syntax and provider registration without making any network calls.

## Caching

Wrap a provider with `NewCachedProvider` to avoid redundant API calls. Cached values are held in memory and reused until the TTL expires. This is especially useful for cloud providers where every `Resolve()` or `Watch` poll cycle would otherwise hit the network.

```go
sm, _ := awssm.New(awssm.WithRegion("us-west-2"))
r := secrets.NewResolver(
    secrets.WithDefault(secrets.NewCachedProvider(sm, 5*time.Minute)),
    secrets.WithProvider("env", env.New()), // no cache needed
)
```

Only successful results are cached — errors always pass through. Call `Clear()` to evict all entries manually. `Close()` clears the cache and closes the underlying provider if it implements `io.Closer`.

## Parallel fetching

Secrets are fetched concurrently (default parallelism: 10). Multiple fields referencing the same secret URI with different `#fragment` values result in a single fetch.

```go
r := secrets.NewResolver(
    secrets.WithDefault(sm),
    secrets.WithParallelism(20),
)
```
