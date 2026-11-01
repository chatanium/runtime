package Util

import (
	"errors"
	"os"

	"github.com/joho/godotenv"
	"github.com/thirdscam/chatanium/src/Util/Log"
)

// InitEnv optionally loads local defaults without replacing provisioned values.
func InitEnv() error {
	err := godotenv.Load(".env")
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return errors.New("cannot load optional .env defaults")
	}
	return nil
}

func GetEnv(EnvName string) string {
	env := os.Getenv(EnvName)
	if env == "" {
		Log.Warn.Printf("CheckEnvExists: Unable to find environment variable: %s", EnvName)
	}
	return env
}
