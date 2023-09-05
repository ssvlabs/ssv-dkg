package initiator

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/bloxapp/ssv-dkg-tool/cli/flags"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/utils"

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
	flags.AddDepositResultStorePathFlag(StartDKG)
	flags.AddSSVPayloadResultStorePathFlag(StartDKG)
	viper.BindPFlag("threshold", StartDKG.PersistentFlags().Lookup("threshold"))
	viper.BindPFlag("withdrawAddress", StartDKG.PersistentFlags().Lookup("withdrawAddress"))
	viper.BindPFlag("operatorIDs", StartDKG.PersistentFlags().Lookup("operatorIDs"))
	viper.BindPFlag("operatorsInfoPath", StartDKG.PersistentFlags().Lookup("operatorsInfoPath"))
	viper.BindPFlag("owner", StartDKG.PersistentFlags().Lookup("owner"))
	viper.BindPFlag("nonce", StartDKG.PersistentFlags().Lookup("nonce"))
	viper.BindPFlag("fork", StartDKG.PersistentFlags().Lookup("fork"))
	viper.BindPFlag("depositResultsPath", StartDKG.PersistentFlags().Lookup("depositResultsPath"))
	viper.BindPFlag("ssvPayloadResultsPath", StartDKG.PersistentFlags().Lookup("ssvPayloadResultsPath"))
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
		// Check paths for results
		depositResultsPath := viper.GetString("depositResultsPath")
		if depositResultsPath == "" {
			logger.Fatal("failed to get deposit result path flag value", zap.Error(err))
		}
		_, err = os.Stat(depositResultsPath)
		if !os.IsNotExist(err) {
			logger.Fatal("Deposit file at provided path already exist", zap.Error(err))
		}
		// Check paths for results
		ssvPayloadResultsPath := viper.GetString("ssvPayloadResultsPath")
		if ssvPayloadResultsPath == "" {
			logger.Fatal("failed to get ssv payload path flag value", zap.Error(err))
		}
		_, err = os.Stat(ssvPayloadResultsPath)
		if !os.IsNotExist(err) {
			logger.Fatal("SSV payload file at provided path already exist", zap.Error(err))
		}
		// Load operators TODO: add more sources.
		operatorFile := viper.GetString("operatorsInfoPath")
		if operatorFile == "" {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}
		opMap, err := load.Operators(operatorFile)
		if err != nil {
			logger.Fatal("Failed to load operators: ", zap.Error(err))
		}
		participants := viper.GetStringSlice("operatorIDs")
		if participants == nil {
			logger.Fatal("failed to get operator IDs flag value", zap.Error(err))
		}
		parts, err := loadParticipants(participants)
		if err != nil {
			logger.Fatal("failed: ", zap.Error(err))
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
		forkHex := viper.GetString("fork")
		if forkHex == "" {
			logger.Fatal("failed to get fork version flag value", zap.Error(err))
		}
		if err != nil {
			logger.Fatal("failed to get fork version flag value", zap.Error(err))
		}
		forkBytes, err := hex.DecodeString(forkHex)
		if err != nil {
			logger.Fatal("failed to get fork version flag value", zap.Error(err))
		}
		var fork [4]byte
		copy(fork[:], forkBytes)
		var forkName string
		switch fork {
		case [4]byte{0x00, 0x00, 0x10, 0x20}:
			forkName = "prater"
		case [4]byte{0, 0, 0, 0}:
			forkName = "mainnet"
		case [4]byte{0x99, 0x99, 0x99, 0x99}:
			forkName = "now_test_network"
		default:
			forkName = "mainnet"
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
		depositData, keyShares, err := dkgClient.StartDKG(withdrawPubKey, parts, threshold, fork, forkName, common.HexToAddress(owner), nonce)

		if err != nil {
			logger.Fatal("failed to initiate DKG ceremony", zap.Error(err))
		}
		// Save deposit file
		logger.Info("DKG finished. All data is validated. Writing deposit data json to file %s\n", zap.String("path", depositResultsPath))
		err = utils.WriteJSON(depositResultsPath, []client.DepositDataJson{*depositData})
		if err != nil {
			logger.Warn("Failed writing deposit data file", zap.Error(err))
		}

		logger.Info("DKG finished. All data is validated. Writing keyshares to file: %s\n", zap.String("path", ssvPayloadResultsPath))
		err = utils.WriteJSON(ssvPayloadResultsPath, keyShares)
		if err != nil {
			logger.Warn("Failed writing keyshares file", zap.Error(err))
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
