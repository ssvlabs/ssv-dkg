package verify

import (
	"fmt"
	"log"
	"os"

	"github.com/aquasecurity/table"
	"github.com/spf13/cobra"

	"github.com/ssvlabs/ssv-dkg/cli/flags"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
)

func init() {
	flags.SetVerifyFlags(Verify)
}

var Verify = &cobra.Command{
	Use:   "verify",
	Short: "Verifies a DKG ceremony directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := flags.BindVerifyFlags(cmd); err != nil {
			return err
		}

		err := validator.ValidateResultsDir(
			flags.CeremonyDir,
			int(flags.Validators),
			flags.OwnerAddress,
			flags.Nonce,
			flags.WithdrawAddress,
		)
		if err != nil {
			log.Printf("Failed to validate ceremony directory: %v", err)
			return err
		}

		log.Printf("Ceremony is valid.")

		tbl := table.New(os.Stdout)
		tbl.SetHeaders("Directory", "Withdrawal Address", "Nonce", "Owner Address", "Validators")
		tbl.AddRow(
			flags.CeremonyDir,
			flags.WithdrawAddress.String(),
			fmt.Sprintf("%d", flags.Nonce),
			flags.OwnerAddress.String(),
			fmt.Sprintf("%d", flags.Validators),
		)
		tbl.Render()

		return nil
	},
}
