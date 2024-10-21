package pepgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"

	"github.com/stevenvegt/pep-go/curve"
)

type ActivationServiceKeys struct {
	// Y is an ElGamal public key called Identity Private Public key
	Y curve.PublicKey

	// Z is an ElGamal public key called Pseudonym Private Public key
	Z curve.PublicKey

	// AAm is an HMAC master key called Authentication provider Adherence Master
	// key. The master key AAM is used by BSN-L to derive for each authentica-
	// tion provider a key AADi called Authentication provider Adherence Derived
	// key. The AADi key ensures that PI/PP/PIPs are authentication provider specific
	AAm curve.HMACKey
}

// IActivationService is an interface for the activation service
// The activation service create polymorphic pseudonyms and identities for the BSN for AuthProviders
type IActivationService interface {
	Activate(ActivationRequest) (ActivationResponse, error)
	SetKeys(ActivationServiceKeys)
	IIdentifiable
}

type ActivationService struct {
	keys ActivationServiceKeys
}

func NewActivationService() IActivationService {
	return &ActivationService{}
}

func calcDerivedKey(key curve.HMACKey, identifier []byte) curve.HMACKey {
	log.Printf("calclDerivedKey, key: %x, identifier: %s\n", key, identifier)
	mac := hmac.New(sha256.New, key.Bytes())
	mac.Write(identifier)
	sum := mac.Sum(nil)
	dk := curve.HMACKey{}
	dk.SetBytes(sum)
	return dk
}

func (as ActivationService) Activate(req ActivationRequest) (ActivationResponse, error) {
	log.Println("OP: Activate")

	// Embed
	p := curve.Embed([]byte(req.Identifier))

	AAdi := calcDerivedKey(as.keys.AAm, []byte(req.APid))

	p = curve.Unshuffle(p, AAdi)

	c, err := curve.Encrypt(as.keys.Y, p)
	if err != nil {
		return ActivationResponse{}, err
	}
	return ActivationResponse{
		PI: c,
	}, nil

}

func (as ActivationService) GetIdentifier() string {
	return "AS1"
}

func (as *ActivationService) SetKeys(keys ActivationServiceKeys) {
	as.keys = keys
}
