package verify

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/table"
	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
)

func init() {
	cli_utils.SetVerifyFlags(Verify)
}

var Verify = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a DKG ceremony directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cli_utils.BindVerifyFlags(cmd); err != nil {
			return err
		}

		err := validator.ValidateResultsDir(
			cli_utils.CeremonyDir,
			int(cli_utils.Validators),
			cli_utils.OwnerAddress,
			cli_utils.Nonce,
			cli_utils.WithdrawAddress,
		)
		if err != nil {
			log.Printf("Failed to validate ceremony directory: %v", err)
			return err
		}

		log.Printf("Ceremony is valid.")

		tbl := table.New(os.Stdout)
		tbl.SetHeaders("Directory", "Withdrawal Address", "Nonce", "Owner Address", "Validators")
		tbl.AddRow(
			cli_utils.CeremonyDir,
			cli_utils.WithdrawAddress.String(),
			fmt.Sprintf("%d", cli_utils.Nonce),
			cli_utils.OwnerAddress.String(),
			fmt.Sprintf("%d", cli_utils.Validators),
		)
		tbl.Render()

		return nil
	},
}
