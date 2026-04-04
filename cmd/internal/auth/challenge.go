package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash"
	"time"

	"golang.org/x/crypto/ssh"
)

const sshsigMagic = "SSHSIG"

type Challenge struct {
	Value     string
	ExpiresAt time.Time
}

func NewChallenge(ttl time.Duration) (Challenge, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Challenge{}, fmt.Errorf("failed to generate random bytes: %w", err)
	}
	return Challenge{
		Value:     hex.EncodeToString(b),
		ExpiresAt: time.Now().Add(ttl),
	}, nil
}

// VerifySignature verifies an sshsig-format signature produced by:
//
//	echo "<message>" | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n <namespace>
func VerifySignature(publicKeyLine string, namespace string, message string, signatureBlock string) error {
	// Parse the authorized-key-format public key.
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(publicKeyLine))
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	// Decode PEM envelope.
	block, _ := pem.Decode([]byte(signatureBlock))
	if block == nil || block.Type != "SSH SIGNATURE" {
		return errors.New("invalid signature block: expected PEM type \"SSH SIGNATURE\"")
	}

	raw := block.Bytes
	if len(raw) < len(sshsigMagic) || string(raw[:len(sshsigMagic)]) != sshsigMagic {
		return errors.New("invalid signature: missing SSHSIG magic preamble")
	}

	// Unmarshal the body after the 6-byte magic preamble.
	var body struct {
		Version       uint32
		PublicKey     []byte
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Signature     []byte
	}
	if err := ssh.Unmarshal(raw[len(sshsigMagic):], &body); err != nil {
		return fmt.Errorf("failed to parse signature body: %w", err)
	}

	if body.Version != 1 {
		return fmt.Errorf("unsupported sshsig version %d", body.Version)
	}

	// The embedded public key must match the one the caller provided.
	signerKey, err := ssh.ParsePublicKey(body.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse embedded public key: %w", err)
	}
	if !bytes.Equal(pubKey.Marshal(), signerKey.Marshal()) {
		return errors.New("public key mismatch: signature was made with a different key")
	}

	if body.Namespace != namespace {
		return fmt.Errorf("namespace mismatch: got %q, want %q", body.Namespace, namespace)
	}

	// Parse the inner SSH signature blob.
	var sshSig ssh.Signature
	if err := ssh.Unmarshal(body.Signature, &sshSig); err != nil {
		return fmt.Errorf("failed to parse ssh signature: %w", err)
	}

	// Hash the message.
	var h hash.Hash
	switch body.HashAlgorithm {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		return fmt.Errorf("unsupported hash algorithm: %s", body.HashAlgorithm)
	}
	h.Write([]byte(message))
	msgHash := h.Sum(nil)

	// Build the verification blob (PROTOCOL.sshsig §4):
	//   byte[6] "SSHSIG"
	//   string  namespace
	//   string  reserved
	//   string  hash_algorithm
	//   string  hash(message)
	verBody := ssh.Marshal(struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		MessageHash   []byte
	}{
		Namespace:     body.Namespace,
		Reserved:      body.Reserved,
		HashAlgorithm: body.HashAlgorithm,
		MessageHash:   msgHash,
	})
	toVerify := append([]byte(sshsigMagic), verBody...)

	return pubKey.Verify(toVerify, &sshSig)
}
