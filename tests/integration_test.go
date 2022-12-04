package ledger_test

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	gethaccounts "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	coretypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/evmos/evmos-ledger-go/accounts"
	"github.com/evmos/evmos-ledger-go/usbwallet"
	"github.com/stretchr/testify/require"
)

// Test Mnemonic:
// glow spread dentist swamp people siren hint muscle first sausage castle metal
// cycle abandon accident logic again around mix dial knee organ episode usual
// (24 words)

func initWallet(t *testing.T, path gethaccounts.DerivationPath) (accounts.Wallet, accounts.Account) {
	t.Helper()

	ledger, err := usbwallet.NewLedgerHub()
	require.NoError(t, err)

	require.NotZero(t, len(ledger.Wallets()))

	wallet := ledger.Wallets()[0]
	err = wallet.Open("")
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

// Test transaction is generated correctly using CreateTx
func TestSanityCreateTx(t *testing.T) {
	addr := "0x3535353535353535353535353535353535353535"

	tx, err := CreateTx(
		3,               // Nonce
		addr,            // To
		10,              // Gas
		big.NewInt(10),  // GasPrice
		big.NewInt(10),  // Value
		make([]byte, 0), // Data
	)
	require.NoError(t, err)

	require.Equal(t, tx.Nonce(), uint64(3))
	require.Equal(t, tx.GasPrice(), big.NewInt(10))
	require.Equal(t, tx.Gas(), uint64(10))

	addrBytes, err := hex.DecodeString(strings.TrimPrefix(addr, "0x"))
	require.NoError(t, err)

	require.Equal(t, tx.To()[:], addrBytes)
	require.Equal(t, tx.To().Hex(), addr)
	require.Equal(t, *tx.Value(), *big.NewInt(10))
	require.Equal(t, tx.Data(), []byte{})
}

func TestInitWallet(t *testing.T) {
	wallet, account := initWallet(t, gethaccounts.DefaultBaseDerivationPath)
	defer wallet.Close()

	pk := hex.EncodeToString(crypto.FromECDSAPub(account.PublicKey))

	require.Equal(t, account.Address.Hex(), "0xbcf6368dF2C2999893064aDe8C4a4b1b6d3C077B")
	require.Equal(t, pk, "0x045f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb")
}

func TestInvalidAccount(t *testing.T) {
	wallet, account := initWallet(t, gethaccounts.DefaultBaseDerivationPath)
	defer wallet.Close()

	account.Address = common.HexToAddress("0x3535353535353535353535353535353535353535")

	sendAddr := "0x3636363636363636363636363636363636363636"
	tx, err := CreateTx(
		3, sendAddr, 10, big.NewInt(10), big.NewInt(10), make([]byte, 0),
	)
	require.NoError(t, err)

	_, err = wallet.SignTx(account, tx, big.NewInt(0))
	require.Error(t, err, "Expected error on signing with invalid account")
}

// Test deriving an account with path "m/44'/60'/0'/0/1"
func TestAlternateDerivation(t *testing.T) {
	path, err := gethaccounts.ParseDerivationPath("m/44'/60'/0'/0/1")
	require.NoError(t, err)

	wallet, account := initWallet(t, path)
	defer wallet.Close()

	addr := crypto.PubkeyToAddress(*account.PublicKey)
	pk := hex.EncodeToString(crypto.FromECDSAPub(account.PublicKey))
	require.Equal(t, pk, "0x044a5236e77ab81e094d7c6cfeac06d2e93fec455d01c7f80e22c592a89b44acebe99c2450425a184e5382362d5c52f5d996f12e73ccfb7694227f31b501e36ed7")
	require.Equal(t, account.Address.Hex(), addr.Hex())
}

func TestLedgerSignTx1(t *testing.T) {
	wallet, account := initWallet(t, gethaccounts.DefaultBaseDerivationPath)
	defer wallet.Close()

	addr := "0x3535353535353535353535353535353535353535"

	tx, err := CreateTx(
		3, addr, 10, big.NewInt(10), big.NewInt(10), make([]byte, 0),
	)
	require.NoError(t, err)

	sigBytes, err := wallet.SignTx(account, tx, big.NewInt(0))
	require.NoError(t, err)

	sigHex := hex.EncodeToString(sigBytes)

	// Test against signature generated using ethers.js
	require.Equal(t, sigHex, "f85d030a0a9435353535353535353535353535353535353535350a801ca02e0b1b0ed24cd450488eb783e6c64ab0f1d681641970aef062434513731e829ca0721e7b6feedc989a8b114f3f622d5a525095b893b8ce81059e682f7333be3508")
}

func TestLedgerSignTx2(t *testing.T) {
	wallet, account := initWallet(t, gethaccounts.DefaultBaseDerivationPath)
	defer wallet.Close()

	addr := "0x4646464646464646464646464646464646464646"

	tx, err := CreateTx(
		8, addr, 50, big.NewInt(5), big.NewInt(70), []byte{4, 6, 8, 10},
	)
	require.NoError(t, err)

	sigBytes, err := wallet.SignTx(account, tx, big.NewInt(0))
	require.NoError(t, err)

	sigHex := hex.EncodeToString(sigBytes)

	// Test against signature generated using ethers.js
	require.Equal(t, sigHex, "f86108053294464646464646464646464646464646464646464646840406080a1ba0a2120857c6a2f9a2cabe59845b4e3925daf5d13394de52f87f2942f2ba4f9de3a031ecb1178393d2b6b4220eda7876f9a719498f4269f6444dfc5c270baec070cc")
}

// Test signing a transaction with a different ChainID
func TestLedgerSignTx3(t *testing.T) {
	wallet, account := initWallet(t, gethaccounts.DefaultBaseDerivationPath)
	defer wallet.Close()

	addr := "0x4646464646464646464646464646464646464646"

	tx, err := CreateTx(
		8, addr, 50, big.NewInt(5), big.NewInt(70), []byte{4, 6, 8, 10},
	)
	require.NoError(t, err)

	sigBytes, err := wallet.SignTx(account, tx, big.NewInt(1))
	require.NoError(t, err)

	sigHex := hex.EncodeToString(sigBytes)

	// Test against signature generated using ethers.js
	require.Equal(t, sigHex, "f86108053294464646464646464646464646464646464646464646840406080a26a0da90a513f9ecb1726bc0e77a88f3b1def3f468e41fd3d3f182703085e1b48feca017743f2d3cb4e4b5090e7bd70357a6c4d1b5bfd79531f47669b9a085b530ef37")
}

// Test signing a transaction from an alternate (not default) derivation path
func TestLedgerSignTx4(t *testing.T) {
	path, err := gethaccounts.ParseDerivationPath("m/44'/60'/0'/0/1")
	if err != nil {
		panic("Could not parse derivation path")
	}

	wallet, account := initWallet(t, path)
	defer wallet.Close()

	sendAddr := "0x4646464646464646464646464646464646464646"
	tx, err := CreateTx(
		8, sendAddr, 50, big.NewInt(5), big.NewInt(70), []byte{4, 6, 8, 10},
	)
	require.NoError(t, err)

	sigBytes, err := wallet.SignTx(account, tx, big.NewInt(0))
	require.NoError(t, err)

	sigHex := hex.EncodeToString(sigBytes)

	// Test against signature generated using ethers.js
	require.Equal(t, sigHex, "f86108053294464646464646464646464646464646464646464646840406080a1ba06eaf33b72493638546d6294b39694c5e420fa55de74af6f1c87739da2582e231a016568d498cebfaa7ed80db99b7be76c31f5b78285cfa1794be3141dfae838f16")
}

func TestLedgerSignTyped1(t *testing.T) {
	wallet, account := initWallet(t, gethaccounts.DefaultBaseDerivationPath)
	defer wallet.Close()

	messageStandard := map[string]interface{}{
		"from": map[string]interface{}{
			"name":   "Cow",
			"wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826",
		},
		"to": map[string]interface{}{
			"name":   "Bob",
			"wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB",
		},
		"contents": "Hello, Bob!",
	}

	typedData := createTypedDataPayload(messageStandard)

	sigBytes, err := wallet.SignTypedData(account, typedData)
	require.NoError(t, err)

	sigHex := hex.EncodeToString(sigBytes)

	require.Equal(t, sigHex, "fb35835539608d309ee5ee4b3dfbbc8cb4b591d7e8c9c745473848cbe1e13b037278226e2d6962b3b19145147314d9872ff853437e3ebd654d44aace09128acd1c")
}

func TestLedgerSignTyped2(t *testing.T) {
	wallet, account := initWallet(t, gethaccounts.DefaultBaseDerivationPath)
	defer wallet.Close()

	messageStandard := map[string]interface{}{
		"from": map[string]interface{}{
			"name":   "Charlie",
			"wallet": "0x1CfC9d8357cBE15E08Bb7084073B7E4ef790B625",
		},
		"to": map[string]interface{}{
			"name":   "Delta",
			"wallet": "0x53Fe71EDEFdF942dDE10834ed4d443A6df391F64",
		},
		"contents": "Message from Charlie to Delta!",
	}

	typedData := createTypedDataPayload(messageStandard)

	sigBytes, err := wallet.SignTypedData(account, typedData)
	require.NoError(t, err)

	sigHex := hex.EncodeToString(sigBytes)

	require.Equal(t, sigHex, "d929a56d69a98f3e491828fbd1555e66ddde17c8928a69704e710a9c34db1ab80314ffccf7014be6c8f819ca9c9603d59aad58cddaa1e6f43c7f66a6b9183c681c")
}

// Test signing TypedData from a non-default derivation path
func TestLedgerSignTyped3(t *testing.T) {
	path, err := gethaccounts.ParseDerivationPath("m/44'/60'/0'/0/1")
	if err != nil {
		panic("Could not parse derivation path")
	}

	wallet, account := initWallet(t, path)
	defer wallet.Close()

	messageStandard := map[string]interface{}{
		"from": map[string]interface{}{
			"name":   "Charlie",
			"wallet": "0x1CfC9d8357cBE15E08Bb7084073B7E4ef790B625",
		},
		"to": map[string]interface{}{
			"name":   "Delta",
			"wallet": "0x53Fe71EDEFdF942dDE10834ed4d443A6df391F64",
		},
		"contents": "Message from Charlie to Delta!",
	}

	typedData := createTypedDataPayload(messageStandard)

	sigBytes, err := wallet.SignTypedData(account, typedData)
	require.NoError(t, err)

	sigHex := hex.EncodeToString(sigBytes)

	require.Equal(t, sigHex, "76984ce659f841975bdab7762ed9cb3c936791d1dcded3c0554147fca7accfdc543313669dcda04350990884e9e10c382fb20b722c123409a97c42ef6df617ca1c")
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
