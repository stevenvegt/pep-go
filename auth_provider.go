package pepgo

import (
	"log"

	"github.com/stevenvegt/pep-go/curve"
)

// IAuthProvider is an interface for the AuthProvider.
// An AuthProvider is responsible for transforming the polymorphic identify or pseudonym into an encrypted identity or pseudonym for specific ServiceProviders
// It is not able to decrypt the BSN itself
type IAuthProvider interface {
	Transform(TransformRequest) (TransformResponse, error)
	IKMARegisterable
}

type AuthProvider struct {
	identifier string
	keys       Keys
}

func NewAuthProvider(id string) IAuthProvider {
	return &AuthProvider{identifier: id}
}

func (ap AuthProvider) Transform(req TransformRequest) (TransformResponse, error) {

	res := curve.Rerandomize(req.PI, ap.keys.Y)

	// "decrypt" the polymorphic Identity for this ServiceProvider
	res = curve.Reshuffle(res, ap.keys.AAdi)
	log.Println("aaid: ", ap.keys.AAdi)

	// IEdi := calcDerivedKey(key curve.HMACKey, identifier string)

	// rekey the polymorphic Identity for the ServiceProvider
	res = curve.ReKey(res, req.ServiceProvider.GetRekey())
	return TransformResponse{
		EI: res,
	}, nil
}

func (ap AuthProvider) GetIdentifier() string {
	return ap.identifier
}

func (ap *AuthProvider) SetKeys(keys Keys) {
	ap.keys = keys
}
