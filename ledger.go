package ledger

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcutil/bech32"

	apitypes "github.com/ethereum/go-ethereum/signer/core/apitypes"
	ethLedger "github.com/evmos/ethereum-ledger-go"
	"github.com/evmos/ethereum-ledger-go/accounts"
	"github.com/evmos/ethermint/ethereum/eip712"
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

// Secp256k1DerivationFn defines the derivation function used on the Cosmos SDK Keyring.
type Secp256k1DerivationFn func() (SECP256K1, error)

func EvmosLedgerDerivation() Secp256k1DerivationFn {
	evmosSECP256K1 := new(EvmosSECP256K1)

	return func() (SECP256K1, error) {
		return evmosSECP256K1.connectToLedgerApp()
	}
}

var _ SECP256K1 = &EvmosSECP256K1{}

// EvmosSECP256K1 defines a wrapper of the Ethereum App to
// for compatibility with Cosmos SDK chains.
type EvmosSECP256K1 struct {
	ledger        *ethLedger.EthereumLedger
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

	// Re-open wallet in case it was closed. Do not handle the error here (see SignSECP256K1)
	_ = e.primaryWallet.Open("")

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

	// Re-open wallet in case it was closed. Ignore the error here (see SignSECP256K1)
	_ = e.primaryWallet.Open("")

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

	// Re-open wallet in case it was closed. Since this errors if the wallet is already open,
	// ignore the error. Any errors due to the wallet being closed will surface later on.
	_ = e.primaryWallet.Open("")

	// Derive requested account
	account, err := e.primaryWallet.Derive(hdPath, true)
	if err != nil {
		return []byte{}, errors.New("unable to derive Ledger address, please open the Ethereum app and retry")
	}

	typedData, err := eip712.GetEIP712TypedDataForMsg(signDocBytes)
	if err != nil {
		return []byte{}, err
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

	// Open wallet for the first time. Unlike with other cases, we want to handle the error here.
	if err := primaryWallet.Open(""); err != nil {
		return nil, err
	}

	e.primaryWallet = primaryWallet

	return e, nil
}

func bytesToHexString(bytes []byte) string {
	return "0x" + strings.ToUpper(hex.EncodeToString(bytes))
}
