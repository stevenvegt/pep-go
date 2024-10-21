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
	SetKeys(AuthProviderKeys)
	IIdentifiable
}

// AuthProviderKeys contains all the keys for an AuthProvider provided by the KeyManagementAuthority
type AuthProviderKeys struct {
	// Y is an ElGamal public key called Identity Private Public key
	Y curve.PublicKey

	// AAdi is an HMAC key called Authentication provider Adherence Derived
	// key. All polymorphic forms (PI/PP/PIPs) are Authentication Specific and
	// this key is required to use these forms.
	AAdi curve.HMACKey

	// IEm is an HMAC key called Identity Encryption Master key. It
	// allows the transformation from Polymorphic Identity (PI) to Encrypted Identity (EI).
	// The master key IEM is used by the authentication provider during a trans-
	// formation (authentication) to derive for each service provider an ephemeral
	// key IEDi called Identity Encryption Derived key. With this key, the authen-
	// tication provider can rekey a polymorphic identity to a form decipherable
	// by the service provider.
	IEm curve.HMACKey

	// PEm is an HMAC key called Pseudonym Encryption Master key. Together
	// with the PSM key it allows the transformation from Polymorphic Pseud-
	// onym (PP) to Encrypted Pseudonym (EP).
	PEm curve.HMACKey

	// PSm is an HMAC key called Pseudonym Shuffle Master key. Together with
	// the PEM key it allows the transformation from Polymorphic Pseudonym
	// (PP) to Encrypted Pseudonym (EP).
	PSm curve.HMACKey
}

type AuthProvider struct {
	identifier string
	keys       AuthProviderKeys
}

func NewAuthProvider(id string) IAuthProvider {
	return &AuthProvider{identifier: id}
}

func (ap AuthProvider) Transform(req TransformRequest) (TransformResponse, error) {
	log.Println("OP: Transform")

	res := curve.Rerandomize(req.PI, ap.keys.Y)

	// "decrypt" the polymorphic Identity for this ServiceProvider
	res = curve.Reshuffle(res, ap.keys.AAdi)

	// Compute IEDi based on Y, IDpi: K1(IEM, IDPi.Recipient|||IDPi.KV|||Y.KV)
	// IEdi, Identity Encryption Derivedkey
	IEdi := calcDerivedKey(ap.keys.IEm, []byte(req.SPIdentity))
	log.Println("IEdi: ", IEdi.Scalar())
	// rekey the polymorphic Identity for the ServiceProvider
	res = curve.ReKey(res, IEdi.Scalar())
	return TransformResponse{
		EI: res,
	}, nil
}

func (ap AuthProvider) GetIdentifier() string {
	return ap.identifier
}

func (ap *AuthProvider) SetKeys(keys AuthProviderKeys) {
	ap.keys = keys
}
