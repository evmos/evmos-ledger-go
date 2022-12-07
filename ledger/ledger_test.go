package ledger_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	sdk "github.com/cosmos/cosmos-sdk/types"
	goethaccounts "github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/evmos/ethermint/app"
	"github.com/evmos/ethermint/encoding"
	"github.com/evmos/ethermint/ethereum/eip712"
	"github.com/evmos/evmos-ledger-go/accounts"
)

// Test Mnemonic:
// glow spread dentist swamp people siren hint muscle first sausage castle metal cycle abandon accident logic again around mix dial knee organ episode usual

// Load encoding config for sign doc encoding/decoding
func init() {
	config := encoding.MakeConfig(app.ModuleBasics)
	eip712.SetEncodingConfig(config)
}

func (suite *LedgerTestSuite) TestClose() {
	testCases := []struct {
		name     string
		mockFunc func()
		expPass  bool
	}{
		{
			"fail - can't find Ledger device",
			func() {
				suite.ledger.PrimaryWallet = nil
			},
			false,
		},
		{
			"pass - wallet closed successfully",
			func() {
				RegisterClose(suite.mockWallet)
			},
			true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			tc.mockFunc()
			err := suite.ledger.Close()
			if tc.expPass {
				suite.Require().NoError(err)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func (suite *LedgerTestSuite) TestSignatures() {
	privKey, err := crypto.GenerateKey()
	suite.Require().NoError(err)
	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	account := accounts.Account{
		Address:   addr,
		PublicKey: &privKey.PublicKey,
	}

	testCases := []struct {
		name     string
		tx       []byte
		mockFunc func()
		expPass  bool
	}{
		{
			"fail - can't find Ledger device",
			suite.txAmino,
			func() {
				suite.ledger.PrimaryWallet = nil
			},
			false,
		},
		{
			"fail - unable to derive Ledger address",
			suite.txAmino,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDeriveError(suite.mockWallet)
			},
			false,
		},
		{
			"fail - error generating signature",
			suite.txAmino,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDerive(suite.mockWallet, addr, &privKey.PublicKey)
				RegisterSignTypedDataError(suite.mockWallet, account, suite.txAmino)
			},
			false,
		},
		{
			"pass - test ledger amino signature",
			suite.txAmino,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDerive(suite.mockWallet, addr, &privKey.PublicKey)
				RegisterSignTypedData(suite.mockWallet, account, suite.txAmino)
			},
			true,
		},
		{
			"pass - test ledger protobuf signature",
			suite.txProtobuf,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDerive(suite.mockWallet, addr, &privKey.PublicKey)
				RegisterSignTypedData(suite.mockWallet, account, suite.txProtobuf)
			},
			true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			tc.mockFunc()
			_, err := suite.ledger.SignSECP256K1(goethaccounts.DefaultBaseDerivationPath, tc.tx)
			if tc.expPass {
				suite.Require().NoError(err)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func (suite *LedgerTestSuite) TestSignatureEquivalence() {
	privKey, err := crypto.GenerateKey()
	suite.Require().NoError(err)
	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	account := accounts.Account{
		Address:   addr,
		PublicKey: &privKey.PublicKey,
	}

	testCases := []struct {
		name       string
		txProtobuf []byte
		txAmino    []byte
		mockFunc   func()
		expPass    bool
	}{
		{
			"pass - signatures are equivalent",
			suite.txProtobuf,
			suite.txAmino,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDerive(suite.mockWallet, addr, &privKey.PublicKey)
				RegisterSignTypedData(suite.mockWallet, account, suite.txProtobuf)
				RegisterSignTypedData(suite.mockWallet, account, suite.txAmino)
			},
			true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			tc.mockFunc()
			protoSignature, err := suite.ledger.SignSECP256K1(goethaccounts.DefaultBaseDerivationPath, tc.txProtobuf)
			suite.Require().NoError(err)
			aminoSignature, err := suite.ledger.SignSECP256K1(goethaccounts.DefaultBaseDerivationPath, tc.txAmino)
			suite.Require().NoError(err)
			if tc.expPass {
				suite.Require().Equal(protoSignature, aminoSignature)
			} else {
				suite.Require().NotEqual(protoSignature, aminoSignature)
			}
		})
	}
}

func (suite *LedgerTestSuite) TestGetAddressPubKeySECP256K1() {
	privKey, err := crypto.GenerateKey()
	suite.Require().NoError(err)

	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	expAddr, err := sdk.Bech32ifyAddressBytes("evmos", common.HexToAddress(addr.String()).Bytes())
	suite.Require().NoError(err)

	testCases := []struct {
		name     string
		expPass  bool
		mockFunc func()
	}{
		{
			"fail - can't find Ledger device",
			false,
			func() {
				suite.ledger.PrimaryWallet = nil
			},
		},
		{
			"fail - unable to derive Ledger address",
			false,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDeriveError(suite.mockWallet)
			},
		},
		{
			"fail - bech32 prefix empty",
			false,
			func() {
				suite.hrp = ""
				RegisterOpen(suite.mockWallet)
				RegisterDerive(suite.mockWallet, addr, &privKey.PublicKey)
			},
		},
		{
			"pass - get ledger address",
			true,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDerive(suite.mockWallet, addr, &privKey.PublicKey)
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			tc.mockFunc()
			_, addr, err := suite.ledger.GetAddressPubKeySECP256K1(goethaccounts.DefaultBaseDerivationPath, suite.hrp)
			if tc.expPass {
				suite.Require().NoError(err, "Could not get wallet address")
				suite.Require().Equal(expAddr, addr)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func (suite *LedgerTestSuite) TestGetPublicKeySECP256K1() {
	privKey, err := crypto.GenerateKey()
	suite.Require().NoError(err)
	addr := crypto.PubkeyToAddress(privKey.PublicKey)
	expPubkeyBz := crypto.FromECDSAPub(&privKey.PublicKey)
	testCases := []struct {
		name     string
		expPass  bool
		mockFunc func()
	}{
		{
			"fail - can't find Ledger device",
			false,
			func() {
				suite.ledger.PrimaryWallet = nil
			},
		},
		{
			"fail - unable to derive Ledger address",
			false,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDeriveError(suite.mockWallet)
			},
		},
		{
			"pass - get ledger public key",
			true,
			func() {
				RegisterOpen(suite.mockWallet)
				RegisterDerive(suite.mockWallet, addr, &privKey.PublicKey)
			},
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			tc.mockFunc()
			pubKeyBz, err := suite.ledger.GetPublicKeySECP256K1(goethaccounts.DefaultBaseDerivationPath)
			if tc.expPass {
				suite.Require().NoError(err, "Could not get wallet address")
				suite.Require().Equal(expPubkeyBz, pubKeyBz)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func verifyTypedDataFields(t *testing.T, typedData apitypes.TypedData) {
	// Verify EIP712 Domain
	chainIdBytes, err := typedData.Domain.ChainId.MarshalText()
	require.NoError(t, err, "Could not unwrap chainID bytes with err: %v\n", err)
	require.Equal(t, "0x2328", string(chainIdBytes))
	require.Equal(t, "Cosmos Web3", typedData.Domain.Name)
	require.Equal(t, "1.0.0", typedData.Domain.Version)
	require.Equal(t, "cosmos", typedData.Domain.VerifyingContract)
	require.Equal(t, "0", typedData.Domain.Salt)

	// Verify EIP712 Message Fields
	accountNum := typedData.Message["account_number"]
	require.Equal(t, "0", accountNum)

	chainId := typedData.Message["chain_id"]
	require.Equal(t, "evmos_9000-1", chainId)

	fee := (typedData.Message["fee"].(map[string]interface{}))
	feePayer := fee["feePayer"]
	require.Equal(t, "cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp", feePayer)

	feeGas := fee["gas"]
	require.Equal(t, "20000", feeGas)

	feeAmount := fee["amount"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, "150", feeAmount["amount"])
	require.Equal(t, "atom", feeAmount["denom"])

	memo := typedData.Message["memo"]
	require.Equal(t, "memo", memo)

	msgs := typedData.Message["msgs"].([]interface{})
	require.Len(t, msgs, 1)

	msg := msgs[0].(map[string]interface{})
	msgType := msg["type"]
	require.Equal(t, "cosmos-sdk/MsgSend", msgType)

	msgVal := msg["value"].(map[string]interface{})
	msgAmount := msgVal["amount"].([]interface{})[0].(map[string]interface{})
	require.Equal(t, "150", msgAmount["amount"])
	require.Equal(t, "atom", msgAmount["denom"])

	msgFrom := msgVal["from_address"]
	require.Equal(t, "cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp", msgFrom)

	msgTo := msgVal["to_address"]
	require.Equal(t, "cosmos10t8ca2w09ykd6ph0agdz5stvgau47whhaggl9a", msgTo)
}
