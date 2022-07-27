package ledger

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/simapp/params"
	"github.com/cosmos/cosmos-sdk/x/auth/legacy/legacytx"

	cosmosTypes "github.com/cosmos/cosmos-sdk/types"
	txTypes "github.com/cosmos/cosmos-sdk/types/tx"

	apitypes "github.com/ethereum/go-ethereum/signer/core/apitypes"
	ethLedger "github.com/evmos/ethereum-ledger-go"
	"github.com/evmos/ethereum-ledger-go/accounts"
	"github.com/evmos/ethermint/encoding"
	"github.com/evmos/ethermint/ethereum/eip712"
	"github.com/evmos/ethermint/types"

	app "github.com/evmos/evmos/v6/app"
)

type SECP256K1 interface {
	Close() error
	// Returns an uncompressed pubkey
	GetPublicKeySECP256K1([]uint32) ([]byte, error)
	// Returns a compressed pubkey and bech32 address (requires user confirmation)
	GetAddressPubKeySECP256K1([]uint32, string) ([]byte, string, error)
	// Signs a message (requires user confirmation)
	SignSECP256K1([]uint32, []byte) ([]byte, error)
}

type EvmosSECP256K1 struct {
	ledger        ethLedger.EthereumLedger
	primaryWallet *accounts.Wallet // This represents the first hardware wallet detected
}

// Closes the associated primary wallet. Any requests on
// the object after a successful Close() should not work
func (e EvmosSECP256K1) Close() error {
	if e.primaryWallet == nil {
		return errors.New("Struct had no wallet to close")
	}

	return (*e.primaryWallet).Close()
}

// Return the public key associated with the address derived from
// the provided hdPath using the primary wallet
func (e EvmosSECP256K1) GetPublicKeySECP256K1(hdPath []uint32) ([]byte, error) {
	if e.primaryWallet == nil {
		return make([]byte, 0), errors.New("Struct has no connected wallet.")
	}

	var (
		account accounts.Account
		err     error
	)

	if account, err = (*e.primaryWallet).Derive(hdPath, true); err != nil {
		return make([]byte, 0), err
	}

	return account.PublicKey.Bytes(), nil
}

// hrp "Human Readable Part" e.g. evmos
func (e EvmosSECP256K1) GetAddressPubKeySECP256K1(hdPath []uint32, hrp string) ([]byte, string, error) {
	if e.primaryWallet == nil {
		return make([]byte, 0), "", errors.New("Struct has no connected wallet.")
	}

	var (
		account accounts.Account
		err     error
	)

	if account, err = (*e.primaryWallet).Derive(hdPath, true); err != nil {
		return make([]byte, 0), "", err
	}

	address, err := bech32.Encode(hrp, account.Address.Bytes())
	if err != nil {
		return make([]byte, 0), "", err
	}

	return account.PublicKey.Bytes(), address, nil
}

func (e EvmosSECP256K1) SignSECP256K1(hdPath []uint32, signDocBytes []byte) ([]byte, error) {
	if e.primaryWallet == nil {
		return make([]byte, 0), errors.New("Struct has no connected wallet.")
	}

	var (
		account   accounts.Account
		typedData apitypes.TypedData
		err       error
	)

	// Derive requested account
	if account, err = (*e.primaryWallet).Derive(hdPath, true); err != nil {
		return make([]byte, 0), err
	}

	if err != nil {
		return make([]byte, 0), err
	}

	// Attempt to decode as both Amino and Protobuf to see which format it's in
	typedDataAmino, errAmino := decodeAminoSignDoc(signDocBytes)
	typedDataProtobuf, errProtobuf := decodeProtobufSignDoc(signDocBytes)

	if errAmino == nil {
		typedData = typedDataAmino
	} else if errProtobuf == nil {
		typedData = typedDataProtobuf
	} else {
		return make([]byte, 0), errors.New(fmt.Sprintf("Could not decode sign doc as either Amino or Protobuf.\n Amino: %v\n Protobuf: %v\n", errAmino, errProtobuf))
	}

	// Sign with EIP712 signature
	signature, err := (*e.primaryWallet).SignTypedData(account, typedData)
	if err != nil {
		fmt.Printf("Got error with signature %v\n", err)
		return make([]byte, 0), err
	}

	return signature, nil
}

func FindEthereumUserLedgerApp() (SECP256K1, error) {
	evmosSECP256K1 := new(EvmosSECP256K1)

	// Instantiate new Ledger object
	ledger, err := ethLedger.New()
	if err != nil {
		return nil, err
	}

	evmosSECP256K1.ledger = *ledger
	wallets := evmosSECP256K1.ledger.Wallets()

	// No wallets detected; throw an error
	if len(wallets) == 0 {
		return nil, errors.New("No hardware wallet detected")
	}

	// Default to use first wallet found
	primaryWallet := wallets[0]

	if err := primaryWallet.Open(""); err != nil {
		return nil, err
	}

	evmosSECP256K1.primaryWallet = &primaryWallet

	return evmosSECP256K1, nil
}

func evmosConfig() params.EncodingConfig {
	encodingConfig := encoding.MakeConfig(app.ModuleBasics)
	return encodingConfig
	// registry := codectypes.NewInterfaceRegistry()
	// types.RegisterInterfaces(registry)
	// return codec.NewProtoCodec(registry)
}

func evmosProtoDecoder() codec.ProtoCodecMarshaler {
	return codec.NewProtoCodec(evmosConfig().InterfaceRegistry)
}

func evmosAminoDecoder() *codec.LegacyAmino {
	return evmosConfig().Amino
}

func decodeAminoSignDoc(signDocBytes []byte) (apitypes.TypedData, error) {
	var (
		aminoDoc legacytx.StdSignDoc
		err      error
	)

	// Initialize amino codec with Evmos registrations
	aminoCodec := evmosAminoDecoder()
	protoDecoder := evmosProtoDecoder()

	err = aminoCodec.UnmarshalJSON(signDocBytes, &aminoDoc)
	if err != nil {
		return apitypes.TypedData{}, err
	}

	// Unwrap fees
	var fees legacytx.StdFee
	err = aminoCodec.UnmarshalJSON(aminoDoc.Fee, &fees)
	if err != nil {
		return apitypes.TypedData{}, err
	}

	if len(aminoDoc.Msgs) != 1 {
		return apitypes.TypedData{}, errors.New(fmt.Sprintf("Invalid number of messages in SignDoc, expected 1 but got %v\n", len(aminoDoc.Msgs)))
	}

	var msg cosmosTypes.Msg
	err = aminoCodec.UnmarshalJSON(aminoDoc.Msgs[0], &msg)
	if err != nil {
		fmt.Printf("Encountered err %v\n", err)
		return apitypes.TypedData{}, err
	}

	// By default, use first address in list of signers to cover fee
	// Currently, support only one signer
	if len(msg.GetSigners()) != 1 {
		return apitypes.TypedData{}, errors.New("Expected exactly one signer for message")
	}
	feePayer := msg.GetSigners()[0]
	feeDelegation := &eip712.FeeDelegationOptions{
		FeePayer: feePayer,
	}

	// Parse ChainID
	chainID, err := types.ParseChainID(aminoDoc.ChainID)
	if err != nil {
		return apitypes.TypedData{}, errors.New("Invalid chain ID passed as argument")
	}

	typedData, err := eip712.WrapTxToTypedData(
		protoDecoder,
		chainID.Uint64(),
		msg,
		signDocBytes, // Amino StdSignDocBytes
		feeDelegation,
	)

	if err != nil {
		return apitypes.TypedData{}, errors.New(fmt.Sprintf("Could not convert to EIP712 representation: %v\n", err))
	}

	return typedData, nil
}

func decodeProtobufSignDoc(signDocBytes []byte) (apitypes.TypedData, error) {
	// Init decoder
	protoDecoder := evmosProtoDecoder()

	// Decode sign doc
	signDoc := &txTypes.SignDoc{}
	err := signDoc.Unmarshal(signDocBytes)
	if err != nil {
		return apitypes.TypedData{}, err
	}

	// Decode auth info
	authInfo := &txTypes.AuthInfo{}
	err = authInfo.Unmarshal(signDoc.AuthInfoBytes)
	if err != nil {
		return apitypes.TypedData{}, err
	}

	// Decode body
	body := &txTypes.TxBody{}
	err = body.Unmarshal(signDoc.BodyBytes)
	if err != nil {
		return apitypes.TypedData{}, err
	}

	// Until support for these fields is added, throw an error at their presence
	if body.TimeoutHeight != 0 || len(body.ExtensionOptions) != 0 || len(body.NonCriticalExtensionOptions) != 0 {
		return apitypes.TypedData{}, errors.New("Body contains unsupported fields: TimeoutHeight, ExtensionOptions, or NonCriticalExtensionOptions")
	}

	// Verify single message
	if len(body.Messages) != 1 {
		return apitypes.TypedData{}, errors.New(fmt.Sprintf("Invalid number of messages, expected 1 got %v\n", len(body.Messages)))
	}

	// Verify single signature (single signer for now)
	if len(authInfo.SignerInfos) != 1 {
		return apitypes.TypedData{}, errors.New(fmt.Sprintf("Invalid number of signers, expected 1 got %v\n", len(authInfo.SignerInfos)))
	}

	// Decode signer info (single signer for now)
	signerInfo := authInfo.SignerInfos[0]

	// Parse ChainID
	chainID, err := types.ParseChainID(signDoc.ChainId)
	if err != nil {
		return apitypes.TypedData{}, errors.New("Invalid chain ID passed as argument")
	}

	// Create StdFee
	stdFee := &legacytx.StdFee{
		Amount: authInfo.Fee.Amount,
		Gas:    authInfo.Fee.GasLimit,
	}

	// Parse Message (single message only)
	var msg cosmosTypes.Msg
	err = protoDecoder.UnpackAny(body.Messages[0], &msg)
	if err != nil {
		return apitypes.TypedData{}, errors.New(fmt.Sprintf("Could not unpack message object with error %v\n", err))
	}

	// Init fee payer
	feePayer := msg.GetSigners()[0]
	feeDelegation := &eip712.FeeDelegationOptions{
		FeePayer: feePayer,
	}

	// Create Legacy SignBytes (expected type for WrapTxToTypedData)
	signBytes := legacytx.StdSignBytes(
		signDoc.ChainId,
		signDoc.AccountNumber,
		signerInfo.Sequence,
		body.TimeoutHeight,
		*stdFee,
		[]cosmosTypes.Msg{msg},
		body.Memo,
	)

	typedData, err := eip712.WrapTxToTypedData(
		protoDecoder,
		chainID.Uint64(),
		msg,
		signBytes,
		feeDelegation,
	)
	if err != nil {
		return apitypes.TypedData{}, err
	}

	return typedData, nil
}
