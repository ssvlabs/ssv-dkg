package flags

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
)

// Flag names.
const (
	logLevel       = "logLevel"
	logFormat      = "logFormat"
	logLevelFormat = "logLevelFormat"
	logFilePath    = "logFilePath"
	configPath     = "configPath"
	outputPath     = "outputPath"
)

// global base flags
var (
	ConfigPath     string
	OutputPath     string
	LogLevel       string
	LogFormat      string
	LogLevelFormat string
	LogFilePath    string
)

func SetBaseFlags(cmd *cobra.Command) {
	OutputPathFlag(cmd)
	ConfigPathFlag(cmd)
	LogLevelFlag(cmd)
	LogFormatFlag(cmd)
	LogLevelFormatFlag(cmd)
	LogFilePathFlag(cmd)
}

// BindFlags binds flags to yaml config parameters
func BindBaseFlags(cmd *cobra.Command) error {
	if err := viper.BindPFlag("outputPath", cmd.PersistentFlags().Lookup("outputPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("configPath", cmd.PersistentFlags().Lookup("configPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logLevel", cmd.PersistentFlags().Lookup("logLevel")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logFormat", cmd.PersistentFlags().Lookup("logFormat")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logLevelFormat", cmd.PersistentFlags().Lookup("logLevelFormat")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logFilePath", cmd.PersistentFlags().Lookup("logFilePath")); err != nil {
		return err
	}
	OutputPath = viper.GetString("outputPath")
	if OutputPath != "" {
		OutputPath = filepath.Clean(OutputPath)
	}
	if !filepath.IsLocal(OutputPath) {
		return fmt.Errorf("😥 wrong OutputPath flag, should be local")
	}
	if err := cli_utils.CreateDirIfNotExist(OutputPath); err != nil {
		return err
	}
	LogLevel = viper.GetString("logLevel")
	LogFormat = viper.GetString("logFormat")
	LogLevelFormat = viper.GetString("logLevelFormat")
	LogFilePath = viper.GetString("logFilePath")
	if !filepath.IsLocal(LogFilePath) {
		return fmt.Errorf("😥 wrong logFilePath flag, should be local")
	}
	return nil
}

// LogLevelFlag logger's log level flag to the command
func LogLevelFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logLevel, "debug", "Defines logger's log level", false)
}

// LogFormatFlag logger's  logger's encoding flag to the command
func LogFormatFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logFormat, "json", "Defines logger's encoding, valid values are 'json' (default) and 'console'", false)
}

// LogLevelFormatFlag logger's level format flag to the command
func LogLevelFormatFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logLevelFormat, "capitalColor", "Defines logger's level format, valid values are 'capitalColor' (default), 'capital' or 'lowercase'", false)
}

// LogFilePathFlag file path to write logs into
func LogFilePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logFilePath, "debug.log", "Defines a file path to write logs into", false)
}

// ConfigPathFlag config path flag to the command
func ConfigPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, configPath, "", "Path to config file", false)
}

// OutputPathFlag sets the path to store resulting files
func OutputPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, outputPath, "./data/output", "Path to store results", false)
}
