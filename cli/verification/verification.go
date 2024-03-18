package verification

import (
	"fmt"

	"github.com/spf13/cobra"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
)

func init() {
	cli_utils.SetVerifyDKGFlags(VerifyDKG)
}

var VerifyDKG = &cobra.Command{
	Use:   "verify-dkg",
	Short: "Verify a DKG ceremony output at the given directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		dir, err := validator.OpenResultsDir(cli_utils.CeremonyDir)
		if err != nil {
			return fmt.Errorf("failed to open results directory: %w", err)
		}

	},
}
