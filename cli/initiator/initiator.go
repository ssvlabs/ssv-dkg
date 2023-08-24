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
	"github.com/spf13/viper"
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
	viper.BindPFlag("threshold", StartDKG.PersistentFlags().Lookup("threshold"))
	viper.BindPFlag("withdrawAddress", StartDKG.PersistentFlags().Lookup("withdrawAddress"))
	viper.BindPFlag("operatorIDs", StartDKG.PersistentFlags().Lookup("operatorIDs"))
	viper.BindPFlag("operatorsInfoPath", StartDKG.PersistentFlags().Lookup("operatorsInfoPath"))
	viper.BindPFlag("owner", StartDKG.PersistentFlags().Lookup("owner"))
	viper.BindPFlag("nonce", StartDKG.PersistentFlags().Lookup("nonce"))
	viper.BindPFlag("fork", StartDKG.PersistentFlags().Lookup("fork"))
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

		viper.SetConfigName("initiator")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./config/")
		err := viper.ReadInConfig()
		if err != nil {
			logger.Fatal("fatal error config file")
		}

		// Load operators TODO: add more sources.
		operatorFile := viper.GetString("operatorsInfoPath")
		if operatorFile == "" {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}
		opMap, err := load.Operators(operatorFile)
		if err != nil {
			log.Fatalf("Failed to load operators: %v", err)
		}
		participants := viper.GetStringSlice("operatorIDs")
		if participants == nil {
			logger.Fatal("failed to get operator IDs flag value", zap.Error(err))
		}
		parts, err := loadParticipants(participants)
		if err != nil {
			log.Fatalf("failed: %v", err)
		}
		dkgClient := client.New(opMap)

		withdrawAddr := viper.GetString("withdrawAddress")
		if withdrawAddr == "" {
			logger.Fatal("failed to get withdrawal address flag value", zap.Error(err))
		}
		threshold := viper.GetUint64("threshold")
		if threshold < 1 {
			logger.Fatal("failed to get threshold flag value", zap.Error(err))
		}
		forkName := viper.GetString("fork")
		if forkName == "" {
			logger.Fatal("failed to get fork version flag value", zap.Error(err))
		}
		var fork [4]byte
		switch forkName {
		case "prater":
			fork = [4]byte{0x00, 0x00, 0x10, 0x20}
		case "mainnet":
			fork = [4]byte{0, 0, 0, 0}
		case "now_test_network":
			fork = [4]byte{0x99, 0x99, 0x99, 0x99}
		default:
			fork = [4]byte{0, 0, 0, 0}
		}
		owner := viper.GetString("owner")
		if owner == "" {
			logger.Fatal("failed to get owner address flag value", zap.Error(err))
		}
		nonce := viper.GetUint64("nonce")
		withdrawPubKey, err := hex.DecodeString(withdrawAddr)
		if err != nil {
			logger.Fatal("failed to decode withdrawal public key", zap.Error(err))
		}
		err = dkgClient.StartDKG(withdrawPubKey, parts, threshold, fork, forkName, common.HexToAddress(owner), nonce, true)

		if err != nil {
			logger.Fatal("failed to initiate DKG ceremony", zap.Error(err))
		}

		logger.Info("DKG protocol finished successfull")
	},
}

func loadParticipants(flagdata []string) ([]uint64, error) {
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
