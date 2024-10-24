package flags

import (
	"github.com/spf13/cobra"
)

func SetHealthCheckFlags(cmd *cobra.Command) {
	AddPersistentStringSliceFlag(cmd, "ip", []string{}, "Operator ip:port", true)
}
