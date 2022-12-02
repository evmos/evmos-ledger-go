package ledger

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	codecTypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptoTypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/simapp/params"
	"github.com/cosmos/cosmos-sdk/types"
	txTypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	auxTx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	bankTypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/evmos/ethereum-ledger-go/accounts"
	"github.com/stretchr/testify/require"
)

// Test Mnemonic:
// glow spread dentist swamp people siren hint muscle first sausage castle metal cycle abandon accident logic again around mix dial knee organ episode usual

func testConfig() params.EncodingConfig {
	config := &params.EncodingConfig{}
	// Init Amino
	amino := codec.NewLegacyAmino()
	amino.RegisterInterface((*types.Msg)(nil), nil)
	amino.RegisterConcrete(&bankTypes.MsgSend{}, "cosmos-sdk/MsgSend", nil)
	// Init Protobuf
	registry := codecTypes.NewInterfaceRegistry()
	registry.RegisterImplementations((*types.Msg)(nil), &bankTypes.MsgSend{})

	config.InterfaceRegistry = registry
	config.Amino = amino

	return *config
}

func newEvmosSecpWithTestConfig() *EvmosSECP256K1 {
	config := testConfig()
	e := new(EvmosSECP256K1)
	e.config = config
	return e
}

func newPubKey(t *testing.T, pk string) (res cryptoTypes.PubKey) {
	pkBytes, err := hex.DecodeString(pk)
	require.NoError(t, err)

	pubkey := &ed25519.PubKey{Key: pkBytes}

	return pubkey
}

func getFakeTxAmino() []byte {
	tmp := fmt.Sprintf(
		`{"account_number":"0","chain_id":"evmos_9000-1","fee":{"amount":[{"amount":"150","denom":"atom"}],"gas":"20000"},"memo":"memo","msgs":[{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"150","denom":"atom"}],"from_address":"cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp","to_address":"cosmos10t8ca2w09ykd6ph0agdz5stvgau47whhaggl9a"}}],"sequence":"6"}`,
	)

	return []byte(tmp)
}

func getFakeTxProtobuf(t *testing.T) []byte {
	marshaler := codec.NewProtoCodec(codecTypes.NewInterfaceRegistry())

	memo := "memo"
	msg := bankTypes.NewMsgSend(
		types.MustAccAddressFromBech32("cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp"),
		types.MustAccAddressFromBech32("cosmos10t8ca2w09ykd6ph0agdz5stvgau47whhaggl9a"),
		[]types.Coin{
			{
				Denom:  "atom",
				Amount: types.NewIntFromUint64(150),
			},
		},
	)

	msgAsAny, err := codecTypes.NewAnyWithValue(msg)
	require.NoError(t, err)

	body := &txTypes.TxBody{
		Messages: [](*codecTypes.Any){
			msgAsAny,
		},
		Memo: memo,
	}

	pubKey := newPubKey(t, "0B485CFC0EECC619440448436F8FC9DF40566F2369E72400281454CB552AFB50")

	pubKeyAsAny, err := codecTypes.NewAnyWithValue(pubKey)
	require.NoError(t, err)

	signingMode := txTypes.ModeInfo_Single_{
		Single: &txTypes.ModeInfo_Single{
			Mode: signing.SignMode_SIGN_MODE_DIRECT,
		},
	}

	signerInfo := &txTypes.SignerInfo{
		PublicKey: pubKeyAsAny,
		ModeInfo: &txTypes.ModeInfo{
			Sum: &signingMode,
		},
		Sequence: 6,
	}

	fee := txTypes.Fee{Amount: types.NewCoins(types.NewInt64Coin("atom", 150)), GasLimit: 20000}

	authInfo := &txTypes.AuthInfo{
		SignerInfos: [](*txTypes.SignerInfo){signerInfo},
		Fee:         &fee,
	}

	bodyBytes := marshaler.MustMarshal(body)
	authInfoBytes := marshaler.MustMarshal(authInfo)

	signBytes, err := auxTx.DirectSignBytes(
		bodyBytes,
		authInfoBytes,
		"evmos_9000-1",
		0,
	)
	require.NoError(t, err)

	return signBytes
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

func TestSanityDecodeBytes(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	typedData, err := e.decodeAminoSignDoc(getFakeTxAmino())
	require.NoError(t, err)

	t.Logf("Typed data %v\n", typedData)
}

func TestLedgerAminoSignature(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer func() {
		err := wallet.Close()
		require.NoError(t, err)
	}()

	require.NoError(t, err, "could not retrieve wallet")

	signature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxAmino())
	require.NoError(t, err, "could not sign bytes")

	t.Logf("Signature %v\n", signature)
}

func TestLedgerProtobufSignature(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer func() {
		err := wallet.Close()
		require.NoError(t, err)
	}()

	require.NoError(t, err, "could not retrieve wallet")

	signature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxProtobuf(t))
	require.NoError(t, err, "could not sign bytes")

	t.Logf("Signature %v\n", signature)
}

func TestProtobufDecodesAmino(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	_, err := e.decodeProtobufSignDoc(getFakeTxAmino())
	require.Error(t, err, "expected to fail decoding Aminos")
}

func TestAminoDecodesProtobuf(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	_, err := e.decodeAminoSignDoc(getFakeTxProtobuf(t))
	require.Error(t, err, "expected to fail decoding Protobuf")
}

func TestProtobufTypedData(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	typedData, err := e.decodeProtobufSignDoc(getFakeTxProtobuf(t))
	require.NoError(t, err, "did not expect to fail decoding Protobuf SignDoc")
	verifyTypedDataFields(t, typedData)
}

func TestAminoTypedData(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	typedData, err := e.decodeAminoSignDoc(getFakeTxAmino())
	require.NoError(t, err, "Did not expect to fail decoding Amino SignDoc")
	verifyTypedDataFields(t, typedData)
}

func TestTypedDataEquivalence(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	protobufTypedData, err := e.decodeProtobufSignDoc(getFakeTxProtobuf(t))
	require.NoError(t, err, "Did not expect to fail decoding Protobuf SignDoc")

	aminoTypedData, err := e.decodeAminoSignDoc(getFakeTxAmino())
	require.NoError(t, err, "Did not expect to fail decoding Amino SignDoc")

	require.Equal(t, protobufTypedData, aminoTypedData, "Unequal typed datas, expected equivalence")
}

func TestPayloadSignaturesEquivalence(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer func() {
		err := wallet.Close()
		require.NoError(t, err)
	}()

	if err != nil {
		require.NoError(t, err, "Could not retrieve wallet")
	}

	protoSignature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxProtobuf(t))
	require.NoError(t, err, "Could not sign Protobuf bytes")

	aminoSignature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxAmino())
	require.NoError(t, err, "Could not sign Amino bytes")

	require.Equal(t, protoSignature, aminoSignature, "Payload signatures are different, expected the same")
}

func TestGetLedgerAddress(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer func() {
		err := wallet.Close()
		require.NoError(t, err)
	}()

	require.NoError(t, err, "Could not retrieve wallet")

	pubkey, addr, err := wallet.GetAddressPubKeySECP256K1(accounts.DefaultBaseDerivationPath, "evmos")
	require.NoError(t, err, "Could not get wallet address")
	require.Equal(t, "evmos1hnmrdr0jc2ve3ycxft0gcjjtrdkncpmmkeamf9", addr)

	hex := hex.EncodeToString(pubkey)
	require.Equal(t,
		"045f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb",
		hex,
	)

	t.Logf("Pub Key: %v\n", pubkey)
	t.Logf("Address: %v\n", addr)
}

func TestGetLedgerPubkey(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer func() {
		err := wallet.Close()
		require.NoError(t, err)
	}()

	require.NoError(t, err, "Could not retrieve wallet")

	pubkey, err := wallet.GetPublicKeySECP256K1(accounts.DefaultBaseDerivationPath)
	require.NoError(t, err, "Could not get wallet address")

	hex := hex.EncodeToString(pubkey)
	require.Equal(t,
		"045f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb",
		hex,
	)
}

// Get the address and public key for a different HD Path
func TestGetAltLedgerAddress(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer func() {
		err := wallet.Close()
		require.NoError(t, err)
	}()

	require.NoError(t, err, "could not retrieve wallet")

	path, err := accounts.ParseDerivationPath("m/44'/60'/0'/0/1")
	require.NoError(t, err, "could not parse derivation path")

	pubkey, addr, err := wallet.GetAddressPubKeySECP256K1(path, "evmos")
	require.NoError(t, err, "could not get wallet address")
	require.Equal(t, "evmos12um6vtmgxpwsm9zkf0khnux4x3ldcpswnkqz3s", addr)

	hex := hex.EncodeToString(pubkey)
	require.Equal(t,
		"044a5236e77ab81e094d7c6cfeac06d2e93fec455d01c7f80e22c592a89b44acebe99c2450425a184e5382362d5c52f5d996f12e73ccfb7694227f31b501e36ed7",
		hex,
	)

	t.Logf("Pub Key: %v\n", pubkey)
	t.Logf("Address: %v\n", addr)
}
