package ledger

// SECP256K1 defines the necessary methods for ledger compatibility
type SECP256K1 interface {
	// Close will close the associated primary wallet
	Close() error
	// GetPublicKeySECP256K1 returns an uncompressed pubkey
	GetPublicKeySECP256K1([]uint32) ([]byte, error)
	// Returns a compressed pubkey and bech32 address (requires user confirmation)
	GetAddressPubKeySECP256K1([]uint32, string) ([]byte, string, error)
	// Signs a message (requires user confirmation)
	SignSECP256K1([]uint32, []byte) ([]byte, error)
}
