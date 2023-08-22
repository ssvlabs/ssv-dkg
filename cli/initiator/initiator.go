package initiator

import (
	"encoding/hex"
	"fmt"
	"log"
	"strconv"

	"github.com/bloxapp/ssv-dkg-tool/cli/flags"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/ethereum/go-ethereum/common"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	flags.ThresholdFlag(StartDKG)
	flags.WithdrawAddressFlag(StartDKG)
	flags.OperatorsInfoFlag(StartDKG)
	flags.OperatorIDsFlag(StartDKG)
	flags.OwnerAddressFlag(StartDKG)
	flags.NonceFlag(StartDKG)
	flags.ForkVersionFlag(StartDKG)
}

var StartDKG = &cobra.Command{
	Use:   "init-dkg",
	Short: "Initiates a DKG protocol to create new distributed key",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(`
		█████╗ ██╗  ██╗ ██████╗     ██╗███╗   ██╗██╗████████╗██╗ █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██║████╗  ██║██║╚══██╔══╝██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║██╔██╗ ██║██║   ██║   ██║███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║██║╚██╗██║██║   ██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ██║██║ ╚████║██║   ██║   ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
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
		threshold, err := flags.GetThresholdFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get owner address flag value", zap.Error(err))
		}
		fork, forkName, err := flags.GetForkVersionFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get fork version flag value", zap.Error(err))
		}

		owner, err := flags.GetOwnerAddressFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get owner address flag value", zap.Error(err))
		}

		nonce, err := flags.GetNonceFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get nonce flag value", zap.Error(err))
		}
		withdrawPubKey, err := hex.DecodeString(withdrawAddr)
		if err != nil {
			logger.Fatal("failed to decode withdrawal public key", zap.Error(err))
		}
		err = dkgClient.StartDKG(withdrawPubKey, parts, threshold, fork, forkName, [20]byte(common.HexToAddress(owner).Bytes()), nonce)

		if err != nil {
			logger.Fatal("failed to initiate DKG ceremony", zap.Error(err))
		}

		logger.Info("DKG protocol finished successfull")
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
