package ledger

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/bech32"
	"github.com/cosmos/cosmos-sdk/codec"
	"github.com/cosmos/cosmos-sdk/simapp/params"
	"github.com/cosmos/cosmos-sdk/x/auth/migrations/legacytx"

	cosmosTypes "github.com/cosmos/cosmos-sdk/types"
	txTypes "github.com/cosmos/cosmos-sdk/types/tx"

	apitypes "github.com/ethereum/go-ethereum/signer/core/apitypes"
	ethLedger "github.com/evmos/ethereum-ledger-go"
	"github.com/evmos/ethereum-ledger-go/accounts"
	"github.com/evmos/ethermint/ethereum/eip712"
	"github.com/evmos/ethermint/types"
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

// LedgerDerivation defines the derivation function used on the Cosmos SDK Keyring.
type LedgerDerivation func() (SECP256K1, error)

func EvmosLedgerDerivation(config params.EncodingConfig) LedgerDerivation {
	evmosSECP256K1 := EvmosSECP256K1{
		config: config,
	}

	return func() (SECP256K1, error) {
		return evmosSECP256K1.connectToLedgerApp()
	}
}

var _ SECP256K1 = &EvmosSECP256K1{}

// EvmosSECP256K1 defines a wrapper of the Ethereum App to
// for compatibility with Cosmos SDK chains.
type EvmosSECP256K1 struct {
	ledger        *ethLedger.EthereumLedger
	config        params.EncodingConfig
	primaryWallet accounts.Wallet
}

// Closes the associated primary wallet. Any requests on
// the object after a successful Close() should not work
func (e EvmosSECP256K1) Close() error {
	if e.primaryWallet == nil {
		return errors.New("could not close Ledger: no wallet found")
	}

	return e.primaryWallet.Close()
}

// Return the public key associated with the address derived from
// the provided hdPath using the primary wallet
func (e EvmosSECP256K1) GetPublicKeySECP256K1(hdPath []uint32) ([]byte, error) {
	if e.primaryWallet == nil {
		return []byte{}, errors.New("could not get Ledger public key: no wallet found")
	}

	// Re-open wallet in case it was closed
	if err := e.primaryWallet.Open(""); err != nil {
		return []byte{}, err
	}

	account, err := e.primaryWallet.Derive(hdPath, true)
	if err != nil {
		return []byte{}, errors.New("unable to derive public key, please retry")
	}

	return account.PublicKey.Bytes(), nil
}

// hrp "Human Readable Part" e.g. evmos
func (e EvmosSECP256K1) GetAddressPubKeySECP256K1(hdPath []uint32, hrp string) ([]byte, string, error) {
	if e.primaryWallet == nil {
		return []byte{}, "", errors.New("could not get Ledger address: no wallet found")
	}

	// Re-open wallet in case it was closed
	if err := e.primaryWallet.Open(""); err != nil {
		return []byte{}, "", err
	}

	account, err := e.primaryWallet.Derive(hdPath, true)
	if err != nil {
		return []byte{}, "", errors.New("unable to derive Ledger address, please open the Ethereum app and retry")
	}

	bech32AddressBytes, err := bech32.ConvertBits(account.Address.Bytes(), 8, 5, true)
	if err != nil {
		return []byte{}, "", fmt.Errorf("unable to convert address to 32-bit representation: %w", err)
	}

	address, err := bech32.Encode(hrp, bech32AddressBytes)
	if err != nil {
		return []byte{}, "", fmt.Errorf("unable to encode address as bech32: %w", err)
	}

	return account.PublicKey.Bytes(), address, nil
}

func (e EvmosSECP256K1) SignSECP256K1(hdPath []uint32, signDocBytes []byte) ([]byte, error) {
	fmt.Printf("Generating payload, please check your Ledger...\n")

	if e.primaryWallet == nil {
		return []byte{}, errors.New("unable to sign with Ledger: no wallet found")
	}

	// Re-open wallet in case it was closed
	if err := e.primaryWallet.Open(""); err != nil {
		return []byte{}, err
	}

	// Derive requested account
	account, err := e.primaryWallet.Derive(hdPath, true)
	if err != nil {
		return []byte{}, errors.New("unable to derive Ledger address, please open the Ethereum app and retry")
	}

	var typedData apitypes.TypedData

	// Attempt to decode as both Amino and Protobuf to see which format it's in
	typedDataAmino, errAmino := e.decodeAminoSignDoc(signDocBytes)
	typedDataProtobuf, errProtobuf := e.decodeProtobufSignDoc(signDocBytes)

	if errAmino == nil {
		typedData = typedDataAmino
	} else if errProtobuf == nil {
		typedData = typedDataProtobuf
	} else {
		return []byte{}, fmt.Errorf("could not encode payload as EIP-712 object\n amino: %v\n protobuf: %v", errAmino, errProtobuf)
	}

	// Display EIP-712 message hash for user to verify
	if err := e.displayEIP712Hash(typedData); err != nil {
		return []byte{}, fmt.Errorf("unable to generate EIP-712 hash for object: %w", err)
	}

	// Sign with EIP712 signature
	signature, err := e.primaryWallet.SignTypedData(account, typedData)
	if err != nil {
		return []byte{}, fmt.Errorf("error generating signature, please retry: %w", err)
	}

	return signature, nil
}

// Helper function to display the EIP-712 hashes; this allows users to verify the hashed message
// they are signing via Ledger.
func (e EvmosSECP256K1) displayEIP712Hash(typedData apitypes.TypedData) error {
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return err
	}
	typedDataHash, err := typedData.HashStruct(typedData.PrimaryType, typedData.Message)
	if err != nil {
		return err
	}

	fmt.Printf("Signing the following payload with EIP-712:\n")
	fmt.Printf("- Domain: %s\n", bytesToHexString(domainSeparator))
	fmt.Printf("- Message: %s\n", bytesToHexString(typedDataHash))

	return nil
}

func (e *EvmosSECP256K1) connectToLedgerApp() (SECP256K1, error) {
	// Instantiate new Ledger object
	ledger, err := ethLedger.New()
	if err != nil {
		return nil, err
	}

	if ledger == nil {
		return nil, errors.New("no hardware wallets detected")
	}

	e.ledger = ledger
	wallets := e.ledger.Wallets()

	// No wallets detected; throw an error
	if len(wallets) == 0 {
		return nil, errors.New("no hardware wallets detected")
	}

	// Default to use first wallet found
	primaryWallet := wallets[0]

	// Re-open wallet in case it was closed
	if err := primaryWallet.Open(""); err != nil {
		return nil, err
	}

	e.primaryWallet = primaryWallet

	return e, nil
}

func (e EvmosSECP256K1) evmosProtoDecoder() codec.ProtoCodecMarshaler {
	return codec.NewProtoCodec(e.config.InterfaceRegistry)
}

func (e EvmosSECP256K1) evmosAminoDecoder() *codec.LegacyAmino {
	return e.config.Amino
}

func (e EvmosSECP256K1) decodeAminoSignDoc(signDocBytes []byte) (apitypes.TypedData, error) {
	var (
		aminoDoc legacytx.StdSignDoc
		err      error
	)

	// Initialize amino codec with Evmos registrations
	aminoCodec := e.evmosAminoDecoder()
	protoDecoder := e.evmosProtoDecoder()

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
		return apitypes.TypedData{}, fmt.Errorf("invalid number of messages in SignDoc, expected 1 but got %v", len(aminoDoc.Msgs))
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
		return apitypes.TypedData{}, fmt.Errorf("invalid number of signers, expected 1 got %d", len(msg.GetSigners()))
	}

	feePayer := msg.GetSigners()[0]
	feeDelegation := &eip712.FeeDelegationOptions{
		FeePayer: feePayer,
	}

	// Parse ChainID
	chainID, err := types.ParseChainID(aminoDoc.ChainID)
	if err != nil {
		return apitypes.TypedData{}, fmt.Errorf("unable to parse chain ID (%s)", chainID)
	}

	typedData, err := eip712.WrapTxToTypedData(
		protoDecoder,
		chainID.Uint64(),
		msg,
		signDocBytes, // Amino StdSignDocBytes
		feeDelegation,
	)
	if err != nil {
		return apitypes.TypedData{}, fmt.Errorf("could not convert to EIP712 object: %w", err)
	}

	return typedData, nil
}

func (e EvmosSECP256K1) decodeProtobufSignDoc(signDocBytes []byte) (apitypes.TypedData, error) {
	// Init decoder
	protoDecoder := e.evmosProtoDecoder()

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
		return apitypes.TypedData{}, errors.New("transaction body contains unsupported fields: TimeoutHeight, ExtensionOptions, or NonCriticalExtensionOptions")
	}

	// Verify single message
	if len(body.Messages) != 1 {
		return apitypes.TypedData{}, fmt.Errorf("invalid number of messages, expected 1 got %d", len(body.Messages))
	}

	// Verify single signature (single signer for now)
	if len(authInfo.SignerInfos) != 1 {
		return apitypes.TypedData{}, fmt.Errorf("invalid number of signers, expected 1 got %d", len(authInfo.SignerInfos))
	}

	// Decode signer info (single signer for now)
	signerInfo := authInfo.SignerInfos[0]

	// Parse ChainID
	chainID, err := types.ParseChainID(signDoc.ChainId)
	if err != nil {
		return apitypes.TypedData{}, fmt.Errorf("unable to parse chain ID (%s)", chainID)
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
		return apitypes.TypedData{}, fmt.Errorf("could not unpack message object: %w", err)
	}

	// Init fee payer
	feePayer := msg.GetSigners()[0]
	feeDelegation := &eip712.FeeDelegationOptions{
		FeePayer: feePayer,
	}

	// Get tip
	tip := authInfo.Tip

	// Create Legacy SignBytes (expected type for WrapTxToTypedData)
	signBytes := legacytx.StdSignBytes(
		signDoc.ChainId,
		signDoc.AccountNumber,
		signerInfo.Sequence,
		body.TimeoutHeight,
		*stdFee,
		[]cosmosTypes.Msg{msg},
		body.Memo,
		tip,
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

func bytesToHexString(bytes []byte) string {
	return "0x" + strings.ToUpper(hex.EncodeToString(bytes))
}
