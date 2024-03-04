package config

import (
	"os"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)


type Config struct {
	Env            string     	 `yaml:"env" env-default:"local"`
	StoragePath    string     	 `yaml:"storage_path" env-required:"true"`
	GRPC           GRPCConfig 	 `yaml:"grpc"`
	MigrationsPath string
	TokenTTL       time.Duration `yaml:"token_ttl" env-default:"1h"`
}

type GRPCConfig struct {
	Port    string           		 `yaml:"port"`
	Timeout time.Duration 		 `yaml:"timeout"`
}

func MustLoadPath(configPath string) *Config {
	// check if file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		panic("config file does not exist: " + configPath)
	}

	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("cannot read config: " + err.Error())
	}

	return &cfg
}
