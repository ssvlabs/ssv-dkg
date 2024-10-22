package flags

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
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
	ResultPathFlag(cmd)
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
	if strings.Contains(OutputPath, "..") {
		return fmt.Errorf("😥 outputPath cant contain traversal")
	}
	if err := cli_utils.CreateDirIfNotExist(OutputPath); err != nil {
		return err
	}
	LogLevel = viper.GetString("logLevel")
	LogFormat = viper.GetString("logFormat")
	LogLevelFormat = viper.GetString("logLevelFormat")
	LogFilePath = viper.GetString("logFilePath")
	if strings.Contains(LogFilePath, "..") {
		return fmt.Errorf("😥 logFilePath cant contain traversal")
	}
	return nil
}
