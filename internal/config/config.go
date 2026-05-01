package config

import (
	"flag"
	"os"
	"strconv"
)

type Config struct {
	WorkloadAPIAddr string
	Port            int
	JWTAudience     string
	LogLevel        string
}

func Load() (*Config, error) {
	return LoadFrom(os.Args[1:], os.Getenv)
}

func LoadFrom(args []string, environ func(string) string) (*Config, error) {
	fs := flag.NewFlagSet("spiffe-info", flag.ContinueOnError)
	c := &Config{}

	fs.StringVar(&c.WorkloadAPIAddr, "workload-api-addr",
		getenv(environ, "SPIFFE_ENDPOINT_SOCKET", "unix:///tmp/spire-agent/public/api.sock"),
		"Workload API socket address (env: SPIFFE_ENDPOINT_SOCKET)")
	fs.IntVar(&c.Port, "port",
		getenvInt(environ, "PORT", 80),
		"HTTP server listen port (env: PORT)")
	fs.StringVar(&c.JWTAudience, "jwt-audience",
		getenv(environ, "JWT_AUDIENCE", "spiffe-info"),
		"Audience for JWT-SVID fetch (env: JWT_AUDIENCE)")
	fs.StringVar(&c.LogLevel, "log-level",
		getenv(environ, "LOG_LEVEL", "info"),
		"Log level: debug, info, warn, error (env: LOG_LEVEL)")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	return c, nil
}

func getenv(environ func(string) string, key, defaultVal string) string {
	if v := environ(key); v != "" {
		return v
	}
	return defaultVal
}

func getenvInt(environ func(string) string, key string, defaultVal int) int {
	v := environ(key)
	if v == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return defaultVal
	}
	return n
}
