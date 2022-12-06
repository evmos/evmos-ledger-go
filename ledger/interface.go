package ledger

type SECP256K1 interface {
	Close() error
	// GetPublicKeySECP256K1 Returns an uncompressed pubkey
	GetPublicKeySECP256K1([]uint32) ([]byte, error)
	// GetAddressPubKeySECP256K1 Returns a compressed pubkey and bech32 address (requires user confirmation)
	GetAddressPubKeySECP256K1([]uint32, string) ([]byte, string, error)
	// SignSECP256K1 Signs a message (requires user confirmation)
	SignSECP256K1([]uint32, []byte) ([]byte, error)
}
