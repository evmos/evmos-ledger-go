package ledger_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	gethaccounts "github.com/ethereum/go-ethereum/accounts"
	coretypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/evmos/evmos-ledger-go/accounts"
	"github.com/evmos/evmos-ledger-go/ledger"
	"github.com/evmos/evmos-ledger-go/usbwallet"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

var s *LedgerTestSuite

type LedgerTestSuite struct {
	suite.Suite

	wrapper *ledger.EvmosSECP256K1

	account accounts.Account
}

func TestLedgerTestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Tests Suite")
}

func (suite *LedgerTestSuite) SetupSuite() {
	hub, err := usbwallet.NewLedgerHub()
	suite.Require().NoError(err)

	wallet, account := initWallet(suite.T(), gethaccounts.DefaultBaseDerivationPath, hub)
	// FIXME
	_ = wallet
	wrapper := &ledger.EvmosSECP256K1{}

	s = &LedgerTestSuite{
		wrapper: wrapper,
		account: account,
	}
}

// Test Mnemonic:
// glow spread dentist swamp people siren hint muscle first sausage castle metal
// cycle abandon accident logic again around mix dial knee organ episode usual
// (24 words)

func initWallet(t *testing.T, path gethaccounts.DerivationPath, ledger *usbwallet.Hub) (accounts.Wallet, accounts.Account) {
	t.Helper()

	require.NotZero(t, len(ledger.Wallets()))

	wallet := ledger.Wallets()[0]
	err := wallet.Open("")
	require.NoError(t, err)

	account, err := wallet.Derive(path, true)
	require.NoError(t, err)

	return wallet, account
}

func createTypedDataPayload(message map[string]interface{}) apitypes.TypedData {
	const primaryType = "Mail"

	domain := apitypes.TypedDataDomain{
		Name:              "Ether Mail",
		Version:           "1",
		ChainId:           math.NewHexOrDecimal256(1),
		VerifyingContract: "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC",
		Salt:              "",
	}

	domainTypes := apitypes.Types{
		"EIP712Domain": {
			{
				Name: "name",
				Type: "string",
			},
			{
				Name: "version",
				Type: "string",
			},
			{
				Name: "chainId",
				Type: "uint256",
			},
			{
				Name: "verifyingContract",
				Type: "address",
			},
		},
		"Person": {
			{
				Name: "name",
				Type: "string",
			},
			{
				Name: "wallet",
				Type: "address",
			},
		},
		"Mail": {
			{
				Name: "from",
				Type: "Person",
			},
			{
				Name: "to",
				Type: "Person",
			},
			{
				Name: "contents",
				Type: "string",
			},
		},
	}

	return apitypes.TypedData{
		Types:       domainTypes,
		PrimaryType: primaryType,
		Domain:      domain,
		Message:     message,
	}
}

func CreateTx(
	nonce uint64,
	to string,
	gas uint64,
	gasPrice *big.Int,
	amount *big.Int,
	data []byte,
) (*coretypes.Transaction, error) {
	if !common.IsHexAddress(to) {
		return nil, fmt.Errorf("invalid 'to' address: %s", to)
	}

	toAddr := common.HexToAddress(to)

	return coretypes.NewTransaction(
		nonce,
		toAddr,
		amount,
		gas,
		gasPrice,
		data,
	), nil
}
