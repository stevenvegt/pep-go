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
	Identifier string
	Keys       Keys
}

func NewAuthProvider(id string) IAuthProvider {
	return &AuthProvider{Identifier: id}
}

func (ap AuthProvider) Transform(req TransformRequest) (TransformResponse, error) {

	res := curve.Rerandomize(req.PI, ap.Keys.Y)

	// "decrypt" the polymorphic Identity for this ServiceProvider
	res = curve.Reshuffle(res, ap.Keys.AAdi)
	log.Println("aaid: ", ap.Keys.AAdi)

	// IEdi := calcDerivedKey(key curve.HMACKey, identifier string)

	// rekey the polymorphic Identity for the ServiceProvider
	res = curve.ReKey(res, req.ServiceProvider.GetRekey())
	return TransformResponse{
		EI: res,
	}, nil
}

func (ap AuthProvider) GetIdentifier() string {
	return ap.Identifier
}

func (ap *AuthProvider) SetKeys(keys Keys) {
	ap.Keys = keys
}
