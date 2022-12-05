package ledger

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/cosmos/cosmos-sdk/codec"
	codecTypes "github.com/cosmos/cosmos-sdk/codec/types"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	cryptoTypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/cosmos/cosmos-sdk/types"
	txTypes "github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/cosmos/cosmos-sdk/types/tx/signing"
	auxTx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	bankTypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"

	"github.com/stretchr/testify/require"
)

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
