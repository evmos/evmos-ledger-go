package ledger

import (
	"encoding/hex"
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

	"github.com/stretchr/testify/require"
)

func newPubKey(t *testing.T, pk string) (res cryptoTypes.PubKey) {
	pkBytes, err := hex.DecodeString(pk)
	require.NoError(t, err)

	pubkey := &ed25519.PubKey{Key: pkBytes}

	return pubkey
}

func getFakeTxAmino() []byte {
	tmp := `{"account_number":"0","chain_id":"evmos_9000-1","fee":{"amount":[{"amount":"150","denom":"atom"}],"gas":"20000"},"memo":"memo","msgs":[{"type":"cosmos-sdk/MsgSend","value":{"amount":[{"amount":"150","denom":"atom"}],"from_address":"cosmos1r5sckdd808qvg7p8d0auaw896zcluqfd7djffp","to_address":"cosmos10t8ca2w09ykd6ph0agdz5stvgau47whhaggl9a"}}],"sequence":"6"}`

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
