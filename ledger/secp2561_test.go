package ledger_test

import (
	"errors"
	cryptoTypes "github.com/cosmos/cosmos-sdk/crypto/types"
	"github.com/evmos/evmos-ledger-go/ledger/mocks"
)

func RegisterSignSECP256K1(secp256k *mocks.SECP256K1, derivationPath []uint32, tx []byte) {
	secp256k.On("SignSECP256K1", derivationPath, tx).
		Return([]byte{0x01}, nil)
}

func RegisterSignSECP256K1Error(secp256k *mocks.SECP256K1, derivationPath []uint32, tx []byte) {
	secp256k.On("SignSECP256K1", derivationPath, tx).
		Return([]byte{}, errors.New("error"))
}

func RegisterGetAddressPubKeySECP256K1(secp256k *mocks.SECP256K1, pubkey cryptoTypes.PubKey, derivationPath []uint32, hrp string) {
	secp256k.On("GetAddressPubKeySECP256K1", derivationPath, hrp).
		Return(pubkey.Bytes(), "evmos1hnmrdr0jc2ve3ycxft0gcjjtrdkncpmmkeamf9", nil)
}
