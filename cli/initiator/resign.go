package initiator

import (
	"context"
	"fmt"
	"path"
	"strconv"
	"time"

	eth2clienthttp "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

func init() {
	cli_utils.SetResignFlags(StartReSign)
}

var StartReSign = &cobra.Command{
	Use:   "resign",
	Short: "Resign data at existing operators",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		▓█████▄  ██ ▄█▀  ▄████     ██▀███  ▓█████   ██████  ██░ ██  ▄▄▄       ██▀███  ▓█████ 
		▒██▀ ██▌ ██▄█▒  ██▒ ▀█▒   ▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▓█   ▀ 
		░██   █▌▓███▄░ ▒██░▄▄▄░   ▓██ ░▄█ ▒▒███   ░ ▓██▄   ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
		░▓█▄   ▌▓██ █▄ ░▓█  ██▓   ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
		░▒████▓ ▒██▒ █▄░▒▓███▀▒   ░██▓ ▒██▒░▒████▒▒██████▒▒░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▒
		▒▒▓  ▒ ▒ ▒▒ ▓▒ ░▒   ▒    ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
		░ ▒  ▒ ░ ░▒ ▒░  ░   ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░ ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
		░ ░  ░ ░ ░░ ░ ░ ░   ░      ░░   ░    ░   ░  ░  ░   ░  ░░ ░  ░   ▒     ░░   ░    ░   
		░    ░  ░         ░       ░        ░  ░      ░   ░  ░  ░      ░  ░   ░        ░  ░
		░`)
		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindResignFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator")
		if err != nil {
			return err
		}
		defer logger.Sync()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		opMap, err := cli_utils.LoadOperators(logger)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		logger.Info("🔑 opening initiator RSA private key file")
		privateKey, err := cli_utils.LoadInitiatorRSAPrivKey(false)
		if err != nil {
			logger.Fatal("😥 Failed to load private key: ", zap.Error(err))
		}
		keyshares, err := cli_utils.LoadKeyShares(cli_utils.KeysharesFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read keyshares json file:", zap.Error(err))
		}
		// Start resigning
		ctx := context.Background()
		httpClient, err := eth2clienthttp.New(ctx,
			// WithAddress supplies the address of the beacon node, in host:port format.
			eth2clienthttp.WithAddress(cli_utils.BeaconNodeAddress),
			// LogLevel supplies the level of logging to carry out.
			eth2clienthttp.WithLogLevel(zerolog.DebugLevel),
			eth2clienthttp.WithTimeout(time.Second*10),
		)
		if err != nil {
			return err
		}
		client := httpClient.(*eth2clienthttp.Service)
		// in loop and save exitMsg somewhere so we can combine them
		pool := pool.NewWithResults[*ResignResult]().WithContext(ctx).WithFirstError().WithMaxGoroutines(maxConcurrency)
		for i := 0; i < len(keyshares.Shares); i++ {
			i := i
			pool.Go(func(ctx context.Context) (*ResignResult, error) {
				// Create new DKG initiator
				dkgInitiator := initiator.New(privateKey, opMap.Clone(), logger, cmd.Version)
				// Create a new ID.
				id := crypto.NewID()
				// Perform the ceremony.
				exitMsg, validator, err := dkgInitiator.StartResigning(id, &keyshares.Shares[i], client, ctx)
				if err != nil {
					return nil, err
				}
				logger.Debug("Resigning completed for validator",
					zap.String("pub", keyshares.Shares[i].PublicKey),
				)
				return &ResignResult{
					validator,
					exitMsg,
				}, nil
			})
		}
		results, err := pool.Wait()
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		for _, res := range results {
			jsonSignedVoluntaryExit := &wire.SignedVoluntaryExitJson{
				Exit: &wire.VoluntaryExitJson{
					Epoch:          strconv.FormatUint(uint64(res.exitMsg.Message.Epoch), 10),
					ValidatorIndex: strconv.FormatUint(uint64(res.exitMsg.Message.ValidatorIndex), 10),
				},
				Signature: hexutil.Encode(res.exitMsg.Signature[:]),
			}
			filepath := path.Join(cli_utils.OutputPath, fmt.Sprintf("validator-exit-%s.json", jsonSignedVoluntaryExit.Exit.ValidatorIndex))
			// b, err := json.Marshal(jsonSignedVoluntaryExit)
			// if err != nil {
			// 	logger.Fatal("failed to marshal JSON signed voluntary exit", zap.Error(err))
			// }
			if err := utils.WriteJSON(filepath, jsonSignedVoluntaryExit); err != nil {
				logger.Fatal("failed to write validator exist json", zap.Error(err))
			}
			logger.Info("Wrote signed validator exit JSON to", zap.String("path", filepath))
		}
		return nil
	},
}

type ResignResult struct {
	validator string
	exitMsg   *phase0.SignedVoluntaryExit
}
