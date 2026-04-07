package flags

import (
	"github.com/spf13/cobra"
)

func SetHealthCheckFlags(cmd *cobra.Command) {
	AddPersistentStringSliceFlag(cmd, "ip", []string{}, "Operator endpoint(s) to ping (https://host:port). If empty, pings all operators from operatorsInfo", false)
	OperatorsInfoFlag(cmd)
	OperatorsInfoPathFlag(cmd)
}
