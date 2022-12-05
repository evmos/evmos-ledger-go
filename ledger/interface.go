package ledger

import "github.com/evmos/evmos-ledger-go/accounts"

type SECP256K1 interface {
	SetPrimaryWallet(wallet accounts.Wallet)
	Close() error
	// Returns an uncompressed pubkey
	GetPublicKeySECP256K1([]uint32) ([]byte, error)
	// Returns a compressed pubkey and bech32 address (requires user confirmation)
	GetAddressPubKeySECP256K1([]uint32, string) ([]byte, string, error)
	// Signs a message (requires user confirmation)
	SignSECP256K1([]uint32, []byte) ([]byte, error)
}
