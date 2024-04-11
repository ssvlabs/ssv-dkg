package initiator

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"time"

	eth2clienthttp "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	ssz "github.com/ferranbt/fastssz"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/rs/zerolog"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
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
		client := httpClient.(*eth2clienthttp.Service)
		epoch, err := client.EpochFromStateID(ctx, "head")
		if err != nil {
			logger.Fatal("😥 Failed to get slot from state ID: ", zap.Error(err))
		}
		// TODO do this in loop
		validatorPubKey := &bls.PublicKey{}
		if err := validatorPubKey.DeserializeHexStr(keyshares.Shares[0].Payload.PublicKey); err != nil {
			logger.Fatal("😥 Failed to deserialize validator public key: ", zap.Error(err))
		}
		pk := phase0.BLSPubKey(validatorPubKey.Serialize())
		validatorMap, err := client.ValidatorsByPubKey(ctx, "head", []phase0.BLSPubKey{pk})
		if err != nil {
			logger.Fatal("😥 Failed to get validator by public key: ", zap.Error(err))
		}
		exitMsg := phase0.VoluntaryExit{
			Epoch:          epoch + 1,
			ValidatorIndex: validatorMap[0].Index,
		}

		root := []ssz.HashRoot{&exitMsg}
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
				exitSig, validator, err := dkgInitiator.StartResigning(id, &keyshares.Shares[i], root)
				if err != nil {
					return nil, err
				}
				logger.Debug("DKG ceremony completed",
					zap.String("id", hex.EncodeToString(id[:])),
				)
				return &ResignResult{
					id:      id,
					valPub:  validator,
					exitSig: exitSig,
				}, nil
			})
		}
		results, err := pool.Wait()
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		for _, res := range results {
			// TODO reconstructs JSON
			signedVoluntaryExit := &phase0.SignedVoluntaryExit{
				Message:   &exitMsg,
				Signature: phase0.BLSSignature(res.exitSig),
			}

			finalPath := fmt.Sprintf("%s/exit-%s.json", cli_utils.OutputPath, res.valPub)
			err := utils.WriteJSON(finalPath, signedVoluntaryExit)
			if err != nil {
				log.Fatal("😥 Failed to write JSON file: ", zap.Error(err)
			}
			logger.Info("Exit message sig", zap.String("validator", hex.EncodeToString(res.valPub)), zap.String("full sig", hex.EncodeToString(res.exitSig)))
		}
		return nil
	},
}

type ResignResult struct {
	id      [24]byte
	valPub  []byte
	exitSig []byte
}
