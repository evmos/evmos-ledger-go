package ledger

import (
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	codecTypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptoTypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types"
	txTypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	auxTx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	bankTypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/evmos/ethereum-ledger-go/accounts"
)

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
		`{"account_number":"0","chain_id":"evmos_9000-1","fee":{"amount":[{"amount":"150","denom":"atom"}],"gas":"20000"},"memo":"memo","msgs":[{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"150","denom":"atom"}],"from_address":"evmos1xqnm0wf0rmntujjmpsz8nr28324qqyzy5k02u0","to_address":"evmos1rn7fmq6he0s4uz9mwzzqwwm7fmmepd39cusn0t"}}],"sequence":"6"}`,
	)

	return []byte(tmp)
}

func getFakeTxProtobuf(t *testing.T) []byte {
	// marshaler := codec.NewProtoCodec(codecTypes.NewInterfaceRegistry())
	marshaler := evmosProtoDecoder()

	memo := "memo"
	msg := bankTypes.NewMsgSend(
		types.MustAccAddressFromBech32("evmos1xqnm0wf0rmntujjmpsz8nr28324qqyzy5k02u0"),
		types.MustAccAddressFromBech32("evmos1rn7fmq6he0s4uz9mwzzqwwm7fmmepd39cusn0t"),
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
	if feePayer != "evmos1xqnm0wf0rmntujjmpsz8nr28324qqyzy5k02u0" {
		t.Errorf("Invalid fee payer, expected 'evmos1xqnm0wf0rmntujjmpsz8nr28324qqyzy5k02u0' but got %v\n", feePayer)
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
	if msgFrom != "evmos1xqnm0wf0rmntujjmpsz8nr28324qqyzy5k02u0" {
		t.Errorf("Invalid message from address, expected 'evmos1xqnm0wf0rmntujjmpsz8nr28324qqyzy5k02u0' but got %v\n", msgFrom)
	}

	msgTo := msgVal["to_address"]
	if msgTo != "evmos1rn7fmq6he0s4uz9mwzzqwwm7fmmepd39cusn0t" {
		t.Errorf("Invalid message to address, expected 'evmos1rn7fmq6he0s4uz9mwzzqwwm7fmmepd39cusn0t' but got %v\n", msgTo)
	}
}

func TestSanityDecodeBytes(t *testing.T) {
	typedData, err := decodeAminoSignDoc(getFakeTxAmino())

	if err != nil {
		panic(fmt.Sprintf("Failed with err %v\n", err))
	}

	fmt.Printf("Typed data %v\n", typedData)
}

func TestLedgerAminoSignature(t *testing.T) {
	wallet, err := FindEthereumUserLedgerApp()
	if err != nil {
		panic(fmt.Sprintf("Could not retrieve wallet with error %v\n", err))
	}

	signature, err := wallet.SignSECP256K1(accounts.LegacyLedgerBaseDerivationPath, getFakeTxAmino())
	if err != nil {
		panic(fmt.Sprintf("Could not sign bytes with error %v\n", err))
	}

	fmt.Printf("Signature %v\n", signature)
}

func TestLedgerProtobufSignature(t *testing.T) {
	wallet, err := FindEthereumUserLedgerApp()
	if err != nil {
		panic(fmt.Sprintf("Could not retrieve wallet with error %v\n", err))
	}

	signature, err := wallet.SignSECP256K1(accounts.LegacyLedgerBaseDerivationPath, getFakeTxProtobuf(t))
	if err != nil {
		panic(fmt.Sprintf("Could not sign bytes with error %v\n", err))
	}

	fmt.Printf("Signature %v\n", signature)
}

func TestProtobufDecodesAmino(t *testing.T) {
	_, err := decodeProtobufSignDoc(getFakeTxAmino())
	if err == nil {
		t.Error("Expected to fail decoding Amino")
	}
}

func TestAminoDecodesProtobuf(t *testing.T) {
	_, err := decodeAminoSignDoc(getFakeTxProtobuf(t))
	if err == nil {
		t.Error("Expected to fail decoding Protobuf")
	}
}

func TestProtobufTypedData(t *testing.T) {
	typedData, err := decodeProtobufSignDoc(getFakeTxProtobuf(t))
	if err != nil {
		t.Errorf("Did not expect to fail decoding Protobuf SignDoc: %v\n", err)
	}

	verifyTypedDataFields(t, typedData)
}

func TestAminoTypedData(t *testing.T) {
	typedData, err := decodeAminoSignDoc(getFakeTxAmino())
	if err != nil {
		t.Errorf("Did not expect to fail decoding Amino SignDoc: %v\n", err)
	}

	verifyTypedDataFields(t, typedData)
}

func TestTypedDataEquivalence(t *testing.T) {
	protobufTypedData, err := decodeProtobufSignDoc(getFakeTxProtobuf(t))
	if err != nil {
		t.Errorf("Did not expect to fail decoding Amino SignDoc: %v\n", err)
	}

	aminoTypedData, err := decodeAminoSignDoc(getFakeTxAmino())
	if err != nil {
		t.Errorf("Did not expect to fail decoding Amino SignDoc: %v\n", err)
	}

	if !reflect.DeepEqual(protobufTypedData, aminoTypedData) {
		t.Errorf("Unequal typed datas, expected equivalence")
	}
}

func TestPayloadSignaturesEquivalence(t *testing.T) {
	wallet, err := FindEthereumUserLedgerApp()
	if err != nil {
		t.Errorf("Could not retrieve wallet with error %v\n", err)
	}

	protoSignature, err := wallet.SignSECP256K1(accounts.LegacyLedgerBaseDerivationPath, getFakeTxProtobuf(t))
	if err != nil {
		t.Errorf("Could not sign Protobuf bytes with error %v\n", err)
	}

	aminoSignature, err := wallet.SignSECP256K1(accounts.LegacyLedgerBaseDerivationPath, getFakeTxAmino())
	if err != nil {
		t.Errorf("Could not sign Amino bytes with error %v\n", err)
	}

	if !reflect.DeepEqual(protoSignature, aminoSignature) {
		t.Errorf("Payload signatures are different, expected the same")
	}
}
