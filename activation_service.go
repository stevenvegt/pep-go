package pepgo

import (
	"crypto/hmac"
	"crypto/sha256"
	"log"

	"github.com/stevenvegt/pep-go/curve"
)

// IActivationService is an interface for the activation service
// The activation service create polymorphic pseudonyms and identities for the BSN for AuthProviders
type IActivationService interface {
	Activate(ActivationRequest) (ActivationResponse, error)
	IKMARegisterable
}

type ActivationService struct {
	keys Keys
}

func NewActivationService() IActivationService {
	return &ActivationService{}
}

func calcDerivedKey(key curve.HMACKey, identifier string) curve.HMACKey {
	log.Printf("calclDerivedKey, id: %s, key: %x\n", identifier, key)
	mac := hmac.New(sha256.New, key.Bytes())
	mac.Write([]byte(identifier))
	sum := mac.Sum(nil)
	dk := curve.HMACKey{}
	dk.SetBytes(sum)
	return dk
}

func (as ActivationService) Activate(req ActivationRequest) (ActivationResponse, error) {
	p := curve.Embed([]byte(req.Identifier))

	aaid := calcDerivedKey(as.keys.AAm, req.AsIdentifier)
	log.Println("aaid: ", aaid)

	p = curve.Unshuffle(p, aaid)

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

func (as *ActivationService) SetKeys(keys Keys) {
	as.keys = keys
}
