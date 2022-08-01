package ledger

import (
	"encoding/hex"
	"fmt"
	"reflect"
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

func newPubKey(pk string) (res cryptoTypes.PubKey) {
	pkBytes, err := hex.DecodeString(pk)
	if err != nil {
		panic(err)
	}

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
	if err != nil {
		panic(fmt.Sprintf("Error converting message to any %v\n", err))
	}

	body := &txTypes.TxBody{
		Messages: [](*codecTypes.Any){
			msgAsAny,
		},
		Memo: memo,
	}

	pubKey := newPubKey("0B485CFC0EECC619440448436F8FC9DF40566F2369E72400281454CB552AFB50")
	pubKeyAsAny, err := codecTypes.NewAnyWithValue(pubKey)
	if err != nil {
		panic(fmt.Sprintf("Error converting pubkey to any %v\n", err))
	}

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

	if err != nil {
		panic(fmt.Sprintf("Error marshaling sign doc %v\n", err))
	}

	return signBytes
}

func verifyTypedDataFields(t *testing.T, typedData apitypes.TypedData) {
	// Verify EIP712 Domain
	chainIdBytes, err := typedData.Domain.ChainId.MarshalText()
	if err != nil {
		t.Errorf("Could not unwrap chainID bytes with err: %v\n", err)
	}

	if string(chainIdBytes) != "0x2328" { // 9000 in hex
		t.Errorf("Invalid chainID, expected 0x2328 but received %v\n", string(chainIdBytes))
	}

	if typedData.Domain.Name != "Cosmos Web3" {
		t.Errorf("Invalid domain name, expected 'Cosmos Web3' but got %v\n", typedData.Domain.Name)
	}

	if typedData.Domain.Version != "1.0.0" {
		t.Errorf("Invalid domain version, expected '1.0.0' but got %v\n", typedData.Domain.Version)
	}

	if typedData.Domain.VerifyingContract != "cosmos" {
		t.Errorf("Invalid verifying contract, expected 'cosmos' but got %v\n", typedData.Domain.VerifyingContract)
	}

	if typedData.Domain.Salt != "0" {
		t.Errorf("Invalid salt, expected '0' but got %v\n", typedData.Domain.Salt)
	}

	// Verify EIP712 Message Fields
	accountNum := typedData.Message["account_number"]
	if accountNum != "0" {
		t.Errorf("Invalid account number, expected 0 but got %v\n", accountNum)
	}

	chainId := typedData.Message["chain_id"]
	if chainId != "evmos_9000-1" {
		t.Errorf("Invalid chain ID, expected 'evmos_9000-1' but got %v\n", chainId)
	}

	fee := (typedData.Message["fee"].(map[string]interface{}))
	feePayer := fee["feePayer"]
	if feePayer != "cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp" {
		t.Errorf("Invalid fee payer, expected 'cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp' but got %v\n", feePayer)
	}

	feeGas := fee["gas"]
	if feeGas != "20000" {
		t.Errorf("Invalid fee gas, expected '20000' but got %v\n", feeGas)
	}

	feeAmount := fee["amount"].([]interface{})[0].(map[string]interface{})
	if feeAmount["amount"] != "150" {
		t.Errorf("Invalid fee amount, expected 150 but got %v\n", feeAmount["amount"])
	}
	if feeAmount["denom"] != "atom" {
		t.Errorf("Invalid fee denom, expected 'atom' but got %v\n", feeAmount["denom"])
	}

	memo := typedData.Message["memo"]
	if memo != "memo" {
		t.Errorf("Invalid memo, expected 'memo' but got %v\n", memo)
	}

	msgs := typedData.Message["msgs"].([]interface{})
	if len(msgs) != 1 {
		t.Errorf("Invalid number of messages, expected 1 but got %v\n", len(msgs))
	}

	msg := msgs[0].(map[string]interface{})
	msgType := msg["type"]
	if msgType != "cosmos-sdk/MsgSend" {
		t.Errorf("Invalid message type, expected 'cosmos-sdk/MsgSend' but got %v\n", msgType)
	}

	msgVal := msg["value"].(map[string]interface{})
	msgAmount := msgVal["amount"].([]interface{})[0].(map[string]interface{})
	if msgAmount["amount"] != "150" {
		t.Errorf("Invalid message amount, expected '150' but got %v\n", msgVal["amount"])
	}

	if msgAmount["denom"] != "atom" {
		t.Errorf("Invalid denom, expected 'atom' but got %v\n", msgVal["denom"])
	}

	msgFrom := msgVal["from_address"]
	if msgFrom != "cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp" {
		t.Errorf("Invalid message from address, expected 'cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp' but got %v\n", msgFrom)
	}

	msgTo := msgVal["to_address"]
	if msgTo != "cosmos10t8ca2w09ykd6ph0agdz5stvgau47whhaggl9a" {
		t.Errorf("Invalid message to address, expected 'cosmos10t8ca2w09ykd6ph0agdz5stvgau47whhaggl9a' but got %v\n", msgTo)
	}
}

func TestSanityDecodeBytes(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	typedData, err := e.decodeAminoSignDoc(getFakeTxAmino())

	if err != nil {
		panic(fmt.Sprintf("Failed with err %v\n", err))
	}

	fmt.Printf("Typed data %v\n", typedData)
}

func TestLedgerAminoSignature(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer wallet.Close()

	if err != nil {
		panic(fmt.Sprintf("Could not retrieve wallet with error %v\n", err))
	}

	signature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxAmino())
	if err != nil {
		panic(fmt.Sprintf("Could not sign bytes with error %v\n", err))
	}

	fmt.Printf("Signature %v\n", signature)
}

func TestLedgerProtobufSignature(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer wallet.Close()

	if err != nil {
		panic(fmt.Sprintf("Could not retrieve wallet with error %v\n", err))
	}

	signature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxProtobuf(t))
	if err != nil {
		panic(fmt.Sprintf("Could not sign bytes with error %v\n", err))
	}

	fmt.Printf("Signature %v\n", signature)
}

func TestProtobufDecodesAmino(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	_, err := e.decodeProtobufSignDoc(getFakeTxAmino())

	if err == nil {
		t.Error("Expected to fail decoding Amino")
	}
}

func TestAminoDecodesProtobuf(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	_, err := e.decodeAminoSignDoc(getFakeTxProtobuf(t))

	if err == nil {
		t.Error("Expected to fail decoding Protobuf")
	}
}

func TestProtobufTypedData(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	typedData, err := e.decodeProtobufSignDoc(getFakeTxProtobuf(t))
	if err != nil {
		t.Errorf("Did not expect to fail decoding Protobuf SignDoc: %v\n", err)
	}

	verifyTypedDataFields(t, typedData)
}

func TestAminoTypedData(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	typedData, err := e.decodeAminoSignDoc(getFakeTxAmino())
	if err != nil {
		t.Errorf("Did not expect to fail decoding Amino SignDoc: %v\n", err)
	}

	verifyTypedDataFields(t, typedData)
}

func TestTypedDataEquivalence(t *testing.T) {
	e := newEvmosSecpWithTestConfig()
	protobufTypedData, err := e.decodeProtobufSignDoc(getFakeTxProtobuf(t))
	if err != nil {
		t.Errorf("Did not expect to fail decoding Amino SignDoc: %v\n", err)
	}

	aminoTypedData, err := e.decodeAminoSignDoc(getFakeTxAmino())
	if err != nil {
		t.Errorf("Did not expect to fail decoding Amino SignDoc: %v\n", err)
	}

	if !reflect.DeepEqual(protobufTypedData, aminoTypedData) {
		t.Errorf("Unequal typed datas, expected equivalence")
	}
}

func TestPayloadSignaturesEquivalence(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer wallet.Close()

	if err != nil {
		t.Errorf("Could not retrieve wallet with error %v\n", err)
	}

	protoSignature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxProtobuf(t))
	if err != nil {
		t.Errorf("Could not sign Protobuf bytes with error %v\n", err)
	}

	aminoSignature, err := wallet.SignSECP256K1(accounts.DefaultBaseDerivationPath, getFakeTxAmino())
	if err != nil {
		t.Errorf("Could not sign Amino bytes with error %v\n", err)
	}

	if !reflect.DeepEqual(protoSignature, aminoSignature) {
		t.Errorf("Payload signatures are different, expected the same")
	}
}

func TestGetLedgerAddress(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer wallet.Close()

	if err != nil {
		t.Errorf("Could not retrieve wallet with error %v\n", err)
	}

	pubkey, addr, err := wallet.GetAddressPubKeySECP256K1(accounts.DefaultBaseDerivationPath, "evmos")

	if err != nil {
		t.Errorf("Could not get wallet address with error %v\n", err)
	}

	t.Logf("Pub Key: %v\n", pubkey)
	t.Logf("Address: %v\n", addr)

	hex := hex.EncodeToString(pubkey)

	if hex != "5f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb" {
		t.Errorf("Invalid public key (check mnemonic)")
	}

	if addr != "evmos1hnmrdr0jc2ve3ycxft0gcjjtrdkncpmmkeamf9" {
		t.Errorf("Invalid address (check mnemonic)")
	}
}

func TestGetLedgerPubkey(t *testing.T) {
	deriveLedger := EvmosLedgerDerivation(testConfig())
	wallet, err := deriveLedger()
	defer wallet.Close()

	if err != nil {
		t.Errorf("Could not retrieve wallet with error %v\n", err)
	}

	pubkey, err := wallet.GetPublicKeySECP256K1(accounts.DefaultBaseDerivationPath)

	if err != nil {
		t.Errorf("Could not get wallet address with error %v\n", err)
	}

	hex := hex.EncodeToString(pubkey)

	if hex != "5f53cbc346997423fe843e2ee6d24fd7832211000a65975ba81d53c87ad1e5c863a5adb3cb919014903f13a68c9a4682b56ff5df3db888a2cbc3dc8fae1ec0fb" {
		t.Errorf("Invalid public key (check mnemonic)")
	}
}
