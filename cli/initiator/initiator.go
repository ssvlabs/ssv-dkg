package initiator

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
)

const (
	// maxConcurrency is the maximum number of DKG inits to run concurrently.
	maxConcurrency = 20
)

func init() {
	cli_utils.SetInitFlags(StartDKG)
}

var StartDKG = &cobra.Command{
	Use:   "init",
	Short: "Initiates a DKG protocol",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		█████╗ ██╗  ██╗ ██████╗     ██╗███╗   ██╗██╗████████╗██╗ █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██║████╗  ██║██║╚══██╔══╝██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║██╔██╗ ██║██║   ██║   ██║███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║██║╚██╗██║██║   ██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ██║██║ ╚████║██║   ██║   ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindInitFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator")
		if err != nil {
			return err
		}
		defer logger.Sync()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		// Load operators TODO: add more sources.
		operatorIDs, err := cli_utils.StingSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		opMap, err := cli_utils.LoadOperators(logger)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		logger.Info("🔑 opening initiator RSA private key file")
		privateKey, err := cli_utils.LoadInitiatorRSAPrivKey(cli_utils.GenerateInitiatorKeyIfNotExisting)
		if err != nil {
			logger.Fatal("😥 Failed to load private key: ", zap.Error(err))
		}
		ethnetwork := e2m_core.MainNetwork
		if cli_utils.Network != "now_test_network" {
			ethnetwork = e2m_core.NetworkFromString(cli_utils.Network)
		}
		// start the ceremony
		ctx := context.Background()
		pool := pool.NewWithResults[*Result]().WithContext(ctx).WithFirstError().WithMaxGoroutines(maxConcurrency)
		for i := 0; i < int(cli_utils.Validators); i++ {
			i := i
			pool.Go(func(ctx context.Context) (*Result, error) {
				// Create new DKG initiator
				dkgInitiator := initiator.New(privateKey, opMap.Clone(), logger, cmd.Version)

				// Create a new ID.
				id := crypto.NewID()
				nonce := cli_utils.Nonce + uint64(i)

				// Perform the ceremony.
				depositData, keyShares, ceremonySigs, err := dkgInitiator.StartDKG(id, cli_utils.WithdrawAddress.Bytes(), operatorIDs, ethnetwork, cli_utils.OwnerAddress, nonce)
				if err != nil {
					return nil, err
				}
				logger.Debug("DKG ceremony completed",
					zap.String("id", hex.EncodeToString(id[:])),
					zap.Uint64("nonce", nonce),
					zap.String("pubkey", depositData.PubKey),
				)
				return &Result{
					id:           id,
					depositData:  depositData,
					keyShares:    keyShares,
					ceremonySigs: ceremonySigs,
					nonce:        nonce,
				}, nil
			})
		}
		results, err := pool.Wait()
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		var depositDataArr []*initiator.DepositDataJson
		var keySharesArr []*initiator.KeyShares
		var ceremonySigsArr []*initiator.CeremonySigs
		var nonces []uint64
		for _, res := range results {
			depositDataArr = append(depositDataArr, res.depositData)
			keySharesArr = append(keySharesArr, res.keyShares)
			ceremonySigsArr = append(ceremonySigsArr, res.ceremonySigs)
			nonces = append(nonces, res.nonce)
		}
		// Save deposit file
		logger.Info("🎯 All data is validated.")
		cli_utils.WriteInitResults(depositDataArr, keySharesArr, nonces, ceremonySigsArr, logger)
		fmt.Println(`
		▓█████▄  ██▓  ██████  ▄████▄   ██▓    ▄▄▄       ██▓ ███▄ ▄███▓▓█████  ██▀███  
		▒██▀ ██▌▓██▒▒██    ▒ ▒██▀ ▀█  ▓██▒   ▒████▄    ▓██▒▓██▒▀█▀ ██▒▓█   ▀ ▓██ ▒ ██▒
		░██   █▌▒██▒░ ▓██▄   ▒▓█    ▄ ▒██░   ▒██  ▀█▄  ▒██▒▓██    ▓██░▒███   ▓██ ░▄█ ▒
		░▓█▄   ▌░██░  ▒   ██▒▒▓▓▄ ▄██▒▒██░   ░██▄▄▄▄██ ░██░▒██    ▒██ ▒▓█  ▄ ▒██▀▀█▄  
		░▒████▓ ░██░▒██████▒▒▒ ▓███▀ ░░██████▒▓█   ▓██▒░██░▒██▒   ░██▒░▒████▒░██▓ ▒██▒
		 ▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▓  ░▒▒   ▓▒█░░▓  ░ ▒░   ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
		 ░ ▒  ▒  ▒ ░░ ░▒  ░ ░  ░  ▒   ░ ░ ▒  ░ ▒   ▒▒ ░ ▒ ░░  ░      ░ ░ ░  ░  ░▒ ░ ▒░
		 ░ ░  ░  ▒ ░░  ░  ░  ░          ░ ░    ░   ▒    ▒ ░░      ░      ░     ░░   ░ 
		   ░     ░        ░  ░ ░          ░  ░     ░  ░ ░         ░      ░  ░   ░     
		 ░                   ░                                                        
		 
		 This tool was not audited.
		 When using distributed key generation you understand all the risks involved with
		 experimental cryptography.  
		 `)
		return nil
	},
}

type Result struct {
	id           [24]byte
	nonce        uint64
	depositData  *initiator.DepositDataJson
	keyShares    *initiator.KeyShares
	ceremonySigs *initiator.CeremonySigs
}
