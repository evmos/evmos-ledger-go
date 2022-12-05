package ledger_test

import (
	"encoding/hex"
	"github.com/evmos/ethereum-ledger-go/accounts"
	"github.com/evmos/ethermint/app"
	"github.com/evmos/ethermint/encoding"
	"github.com/evmos/ethermint/ethereum/eip712"
)

// Test Mnemonic:
// glow spread dentist swamp people siren hint muscle first sausage castle metal cycle abandon accident logic again around mix dial knee organ episode usual

// Load encoding config for sign doc encoding/decoding
func init() {
	config := encoding.MakeConfig(app.ModuleBasics)
	eip712.SetEncodingConfig(config)
}

func (suite *LedgerTestSuite) TestSignatures() {
	testCases := []struct {
		name    string
		tx      []byte
		expPass bool
	}{
		{
			"pass - test ledger amino signature",
			suite.txAmino,
			true,
		},
		{
			"pass - test ledger protobuf signature",
			suite.txProtobuf,
			true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			_, err := suite.ledger.SignSECP256K1(accounts.DefaultBaseDerivationPath, tc.tx)
			if tc.expPass {
				suite.Require().NoError(err)
			} else {
				suite.Require().Error(err)
			}
		})
	}
}

func (suite *LedgerTestSuite) TestSignatureEquivalence() {
	testCases := []struct {
		name       string
		txProtobuf []byte
		txAmino    []byte
		expPass    bool
	}{
		{
			"pass - signatures are equivalent",
			suite.txProtobuf,
			suite.txAmino,
			true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset
			protoSignature, err := suite.ledger.SignSECP256K1(accounts.DefaultBaseDerivationPath, tc.txProtobuf)
			suite.Require().NoError(err)
			aminoSignature, err := suite.ledger.SignSECP256K1(accounts.DefaultBaseDerivationPath, tc.txAmino)
			suite.Require().NoError(err)
			if tc.expPass {
				suite.Require().Equal(protoSignature, aminoSignature)
			} else {
				suite.Require().NotEqual(protoSignature, aminoSignature)
			}
		})
	}
}

func (suite *LedgerTestSuite) TestGetLedgerAddress() {
	testCases := []struct {
		name    string
		expPass bool
	}{
		{
			"pass - get ledger address",
			true,
		},
	}

	for _, tc := range testCases {
		suite.Run(tc.name, func() {
			suite.SetupTest() // reset

			pubkey, addr, err := suite.ledger.GetAddressPubKeySECP256K1(accounts.DefaultBaseDerivationPath, "evmos")
			suite.Require().NoError(err, "Could not get wallet address")
			suite.Require().Equal("evmos1hnmrdr0jc2ve3ycxft0gcjjtrdkncpmmkeamf9", addr)

			hex := hex.EncodeToString(pubkey)
			suite.Require().Equal(
				"045f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb",
				hex,
			)
		})
	}
}

//func TestLedgerAminoSignature(t *testing.T) {
//	deriveLedger := EvmosLedgerDerivation()
//	wallet, err := deriveLedger()
//	require.NoError(t, err, "could not retrieve wallet")
//	defer func() {
//		require.NotNil(t, wallet)
//		err := wallet.Close()
//		require.NoError(t, err)
//	}()
//
//	require.NoError(t, err, "could not retrieve wallet")
//
//	signature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getMockTxAmino())
//	require.NoError(t, err, "could not sign bytes")
//
//	t.Logf("Signature %v\n", signature)
//}
//
//func TestLedgerProtobufSignature(t *testing.T) {
//	deriveLedger := EvmosLedgerDerivation()
//	wallet, err := deriveLedger()
//	require.NoError(t, err, "could not retrieve wallet")
//	defer func() {
//		require.NotNil(t, wallet)
//		err := wallet.Close()
//		require.NoError(t, err)
//	}()
//
//	signature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getMockTxProtobuf(t))
//	require.NoError(t, err, "could not sign bytes")
//
//	t.Logf("Signature %v\n", signature)
//}
//
//func TestPayloadSignaturesEquivalence(t *testing.T) {
//	deriveLedger := EvmosLedgerDerivation()
//	wallet, err := deriveLedger()
//	require.NoError(t, err, "could not retrieve wallet")
//	defer func() {
//		require.NotNil(t, wallet)
//		err := wallet.Close()
//		require.NoError(t, err)
//	}()
//
//	protoSignature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getMockTxProtobuf(t))
//	require.NoError(t, err, "Could not sign Protobuf bytes")
//
//	aminoSignature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getMockTxAmino())
//	require.NoError(t, err, "Could not sign Amino bytes")
//
//	require.Equal(t, protoSignature, aminoSignature, "Payload signatures are different, expected the same")
//}
//
//func TestGetLedgerAddress(t *testing.T) {
//	deriveLedger := EvmosLedgerDerivation()
//	wallet, err := deriveLedger()
//	require.NoError(t, err, "could not retrieve wallet")
//	defer func() {
//		require.NotNil(t, wallet)
//		err := wallet.Close()
//		require.NoError(t, err)
//	}()
//
//	pubkey, addr, err := wallet.GetAddressPubKeySECP256K1(accounts.DefaultBaseDerivationPath, "evmos")
//	require.NoError(t, err, "Could not get wallet address")
//	require.Equal(t, "evmos1hnmrdr0jc2ve3ycxft0gcjjtrdkncpmmkeamf9", addr)
//
//	hex := hex.EncodeToString(pubkey)
//	require.Equal(t,
//		"045f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb",
//		hex,
//	)
//
//	t.Logf("Pub Key: %v\n", pubkey)
//	t.Logf("Address: %v\n", addr)
//}
//
//func TestGetLedgerPubkey(t *testing.T) {
//	deriveLedger := EvmosLedgerDerivation()
//	wallet, err := deriveLedger()
//	require.NoError(t, err, "could not retrieve wallet")
//	defer func() {
//		require.NotNil(t, wallet)
//		err := wallet.Close()
//		require.NoError(t, err)
//	}()
//
//	pubkey, err := wallet.GetPublicKeySECP256K1(accounts.DefaultBaseDerivationPath)
//	require.NoError(t, err, "Could not get wallet address")
//
//	hex := hex.EncodeToString(pubkey)
//	require.Equal(t,
//		"045f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb",
//		hex,
//	)
//}
//
//// Get the address and public key for a different HD Path
//func TestGetAltLedgerAddress(t *testing.T) {
//	deriveLedger := EvmosLedgerDerivation()
//	wallet, err := deriveLedger()
//	require.NoError(t, err, "could not retrieve wallet")
//	defer func() {
//		require.NotNil(t, wallet)
//		err := wallet.Close()
//		require.NoError(t, err)
//	}()
//
//	path, err := accounts.ParseDerivationPath("m/44'/60'/0'/0/1")
//	require.NoError(t, err, "could not parse derivation path")
//
//	pubkey, addr, err := wallet.GetAddressPubKeySECP256K1(path, "evmos")
//	require.NoError(t, err, "could not get wallet address")
//	require.Equal(t, "evmos12um6vtmgxpwsm9zkf0khnux4x3ldcpswnkqz3s", addr)
//
//	hex := hex.EncodeToString(pubkey)
//	require.Equal(t,
//		"044a5236e77ab81e094d7c6cfeac06d2e93fec455d01c7f80e22c592a89b44acebe99c2450425a184e5382362d5c52f5d996f12e73ccfb7694227f31b501e36ed7",
//		hex,
//	)
//
//	t.Logf("Pub Key: %v\n", pubkey)
//	t.Logf("Address: %v\n", addr)
//}
