package initiator

import (
	"fmt"
	"log"
	"strconv"

	"github.com/bloxapp/ssv-dkg-tool/cli/flags"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	flags.ThresholdFlag(StartDKG)
	flags.WithdrawAddressFlag(StartDKG)
	flags.OperatorsInfoFlag(StartDKG)
	flags.OperatorIDsFlag(StartDKG)
}

var StartDKG = &cobra.Command{
	Use:   "init-dkg",
	Short: "Inititates a DKG protocol to create new distributed key",
	Run: func(cmd *cobra.Command, args []string) {
		if err := logging.SetGlobalLogger("debug", "capital", "console"); err != nil {
			log.Fatal(err)
		}
		logger := zap.L().Named(cmd.Short)
		// Load operators TODO: add more sources.
		operatorFile, err := flags.GetOperatorsInfoFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}
		opMap, err := load.Operators(operatorFile)
		if err != nil {
			log.Fatalf("Failed to load operators: %v", err)
		}
		participants, err := flags.GetoperatorIDsFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get operator IDs flag value", zap.Error(err))
		}
		parts, err := loadParticipants(participants)

		if err != nil {
			log.Fatalf("failed: %v", err)
		}

		dkgClient := client.New(opMap)

		withdrawAddr, err := flags.GetWithdrawAddressFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get withdrawal address flag value", zap.Error(err))
		}

		err = dkgClient.StartDKG([]byte(withdrawAddr), parts)

		if err != nil {
			logger.Fatal("failed to initiate DKG ceremony", zap.Error(err))
		}

		logger.Info("DKG protocol initiated")
	},
}

func loadParticipants(flagdata []string) ([]uint64, error) {
	fmt.Println("Operator IDs", flagdata)
	partsarr := make([]uint64, 0, len(flagdata))
	for i := 0; i < len(flagdata); i++ {
		opid, err := strconv.ParseUint(flagdata[i], 10, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("cant load operator err: %v , data: %v, ", err, flagdata[i])
		}
		partsarr = append(partsarr, opid)
	}
	return partsarr, nil
}
