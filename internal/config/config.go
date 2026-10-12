package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all runtime configuration for Cerberus Sentinel.
type Config struct {
	ServerHost            string
	ServerPort            int
	DBPath                string
	NetworkCIDR           string
	DiscoveryInterval     time.Duration
	VulnerabilityInterval time.Duration
	NmapPath              string
	VulnScript            string
	ForceUnprivileged     bool
	ScanTimeout           time.Duration
	SeedMockData          bool
}

// Load returns configuration populated with defaults and overridden by environment variables.
func Load() *Config {
	cfg := &Config{
		ServerHost:            getEnv("CERBERUS_HOST", "0.0.0.0"),
		ServerPort:            getEnvInt("CERBERUS_PORT", 8080),
		DBPath:                getEnv("CERBERUS_DB_PATH", "cerberus.db"),
		NetworkCIDR:           getEnv("CERBERUS_SUBNET", "172.28.0.0/24"),
		DiscoveryInterval:     getEnvDuration("CERBERUS_DISCOVERY_INTERVAL", 5*time.Minute),
		VulnerabilityInterval: getEnvDuration("CERBERUS_VULN_INTERVAL", 5*time.Minute),
		NmapPath:              getEnv("CERBERUS_NMAP_PATH", "nmap"),
		VulnScript:            getEnv("CERBERUS_VULN_SCRIPT", "vulners"),
		ForceUnprivileged:     getEnvBool("CERBERUS_UNPRIVILEGED", false),
		ScanTimeout:           getEnvDuration("CERBERUS_SCAN_TIMEOUT", 15*time.Minute),
		SeedMockData:          getEnvBool("CERBERUS_MOCK_DATA", false),
	}

	return cfg
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func getEnvDuration(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok && val != "" {
		if b, err := strconv.ParseBool(val); err == nil {
			return b
		}
	}
	return defaultVal
}
