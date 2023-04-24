package bn256

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"

	"golang.org/x/crypto/bn256"

	"github.com/cometbft/cometbft/crypto"
	cmtjson "github.com/cometbft/cometbft/libs/json"
)

const (
	PrivKeyName = "tendermint/PrivKeyBn256"
	PubKeyName  = "tendermint/PubKeyBn256"
	KeyType     = "bn256"
	PubKeySize  = 128
	PrivKeySize = 32
)

var _ crypto.PrivKey = PrivKey{}

type PrivKey []byte

func (PrivKey) TypeTag() string { return PrivKeyName }

func (privKey PrivKey) Bytes() []byte {
	return []byte(privKey)
}

func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	s := new(big.Int)
	s = s.SetBytes(privKey)
	hashed := hashedMessage(msg)
	p := new(bn256.G1)
	p = p.ScalarMult(hashed, s)
	return p.Marshal(), nil
}

func (privKey PrivKey) PubKey() crypto.PubKey {
	s := new(big.Int)
	s.SetBytes(privKey)
	return PubKey(new(bn256.G2).ScalarBaseMult(s).Marshal())
}

func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherEd, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherEd[:]) == 1
	}
	return false
}

func (privKey PrivKey) Type() string {
	return KeyType
}

var _ crypto.PubKey = PubKey{}

type PubKey []byte

func (PubKey) TypeTag() string { return PubKeyName }

// Raw public key
func (pubKey PubKey) Address() crypto.Address {
	return crypto.AddressHash(pubKey)
}

// Bytes returns the PubKey byte format.
func (pubKey PubKey) Bytes() []byte {
	return pubKey
}

// e(h(m), sk*G2)
// e(sk*h(m), -G2)
// e(h(m), sk*G2)*e(sk*h(m), -G2) = 1_GT
// e(h(m), G2)^sk*e(h(m), G2)^(-sk) = 1_GT
func (pubKey PubKey) VerifySignature(msg []byte, sig []byte) bool {
	hashedMessage := hashedMessage(msg)
	public := new(bn256.G2)
	public, valid := public.Unmarshal(pubKey)
	if !valid {
		return false
	}
	leftPair := bn256.Pair(hashedMessage, public).Marshal()
	signedHM := new(bn256.G1)
	signedHM, valid = signedHM.Unmarshal(sig)
	if !valid {
		return false
	}
	rightPair := bn256.Pair(signedHM, G2Base).Marshal()
	if !bytes.Equal(leftPair, rightPair) {
		return false
	}
	return true
}

func (pubKey PubKey) String() string {
	return fmt.Sprintf("PubKeyBn256{%X}", []byte(pubKey))
}

func (pubKey PubKey) Type() string {
	return KeyType
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherEd, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], otherEd[:])
	}
	return false
}

func GenPrivKey() PrivKey {
	secret, _, err := bn256.RandomG2(rand.Reader)
	if err != nil {
		panic("bro")
	}
	return PrivKey(secret.Bytes())
}

// G2Base is the base point computed from  in the golang library with
// ScalarMultBase(1)
var G2Base *bn256.G2

// Hash is the hash function used to digest a message before mapping it to a
// point.
var Hash = sha256.New

func init() {
	cmtjson.RegisterType(PubKey{}, PubKeyName)
	cmtjson.RegisterType(PrivKey{}, PrivKeyName)
	G2Base = new(bn256.G2)
	exp := big.NewInt(1)
	G2Base.ScalarBaseMult(exp)
}

// hashedMessage returns the message hashed to G1
// XXX: this should be fixed as to have a method that maps a message
// (potentially a digest) to a point WITHOUT knowing the corresponding scalar.
// see issue https://github.com/ConsenSys/handel/issues/122
func hashedMessage(msg []byte) *bn256.G1 {
	var point *bn256.G1
	var err error
	var i = 0
	for {
		h := Hash()
		h.Write([]byte(fmt.Sprintf("%v%d", msg, i)))
		hashed := h.Sum(nil)
		reader := bytes.NewBuffer(hashed)
		_, point, err = bn256.RandomG1(reader)
		if err != nil {
			i++
			continue
		}
		break
	}
	return point
}
