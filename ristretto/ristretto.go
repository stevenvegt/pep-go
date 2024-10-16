package ristretto

import (
	"errors"
	"io"

	"github.com/bwesterb/go-ristretto"
)

type PublicKey = ristretto.Point
type PrivateKey = ristretto.Scalar
type Rekey = ristretto.Scalar

type KeyPair struct {
	PrivateKey PrivateKey
	PublicKey  PublicKey
}

type Cryptogram struct {
	A, B, C ristretto.Point
}

type Message = ristretto.Point

type HMACKey [32]byte

func (k *HMACKey) Rand() {
	s := ristretto.Scalar{}
	s.Rand()
	b := s.Bytes()
	k.SetBytes(b[:])
}

func (k *HMACKey) Bytes() []byte {
	return k[:]
}

func (k *HMACKey) SetBytes(b []byte) {
	copy(k[:], b[:])
}

func (k HMACKey) Scalar() ristretto.Scalar {
	s := ristretto.Scalar{}
	b := [32]byte(k)
	s.SetBytes(&b)
	return s
}

func KeyGen() KeyPair {
	var secretKey PrivateKey
	var publicKey PublicKey

	secretKey.Rand()                     // generate a new secret key
	publicKey.ScalarMultBase(&secretKey) // compute public key
	return KeyPair{PrivateKey: secretKey, PublicKey: publicKey}
}

func MultiplyKey(priv PrivateKey, k Rekey) PrivateKey {
	var key ristretto.Scalar
	key.Mul(&priv, &k)
	return key
}

func Embed(msg []byte) ristretto.Point {
	em := [16]byte{}
	copy(em[:], msg)

	m := ristretto.Point{}
	m.SetLizard(&em)
	return m
}

func Reshuffle(c Cryptogram, k HMACKey) Cryptogram {
	s := k.Scalar()

	var c1 ristretto.Point
	var c2 ristretto.Point
	var c3 ristretto.Point

	c1.ScalarMult(&c.A, &s)
	c2.ScalarMult(&c.B, &s)
	c3.Set(&c.C)

	return Cryptogram{A: c1, B: c2, C: c3}
}

func Rerandomize(c Cryptogram, pub PublicKey) Cryptogram {
	var s ristretto.Scalar
	s.Rand()

	var c1 ristretto.Point
	var c2 ristretto.Point
	var c3 ristretto.Point

	tmp := ristretto.Point{}
	tmp.ScalarMultBase(&s)
	c1.Add(&c.A, &tmp)

	tmp = ristretto.Point{}
	tmp.ScalarMult(&pub, &s)
	c2.Add(&c.B, &tmp)

	c3.Set(&pub)

	return Cryptogram{A: c1, B: c2, C: c3}
}

func Unshuffle(p Message, y HMACKey) Message {
	k := y.Scalar()
	k.Inverse(&k)
	return *p.ScalarMult(&p, &k)
}

func Encrypt(pub PublicKey, m Message) (Cryptogram, error) {
	// c1 = t
	// s = pub * t
	// c2 = msg + s
	// c3 = pub

	var t ristretto.Scalar
	t.Rand()

	var c1 ristretto.Point
	var c2 ristretto.Point
	var s ristretto.Point

	c1.ScalarMultBase(&t)
	s.ScalarMult(&pub, &t)
	c2.Add(&s, &m)

	return Cryptogram{A: c1, B: c2, C: pub}, nil
}

func Decrypt(priv PrivateKey, c Cryptogram) ([]byte, error) {
	// y = priv
	// M = D(<A,B,C>) = B - y * A
	// s = y * c_1
	// M = c_2 - s

	c1 := c.A
	c2 := c.B

	var s, m ristretto.Point
	s.ScalarMult(&c1, &priv)
	m.Sub(&c2, &s)

	msg := m.Lizard()
	if msg == nil {
		return nil, errors.New("failed to decrypt, no lizard data")
	}
	return msg, nil
}

func ReKey(c Cryptogram, k Rekey) Cryptogram {
	// RK(〈A,B,C〉,k) = 〈A^(-1)^y, B, C^y〉
	// RK( <A,B,C>, k) = <g^k, B*y^k, C^y>

	var c1 ristretto.Point
	var c2 ristretto.Point
	var c3 ristretto.Point

	kInverse := ristretto.Scalar{}
	kInverse.Inverse(&k)

	c1.ScalarMult(&c.A, &kInverse)
	c2.Set(&c.B)
	c3.ScalarMult(&c.C, &k)

	return Cryptogram{A: c1, B: c2, C: c3}
}

// nonZeroRandomBytes fills the given slice with non-zero random octets.
func nonZeroRandomBytes(s []byte, rand io.Reader) (err error) {
	_, err = io.ReadFull(rand, s)
	if err != nil {
		return
	}

	for i := 0; i < len(s); i++ {
		for s[i] == 0 {
			_, err = io.ReadFull(rand, s[i:i+1])
			if err != nil {
				return
			}
		}
	}

	return
}
