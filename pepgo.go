package pepgo

import (
	"github.com/stevenvegt/pep-go/curve"
)

type Pseudonym struct {
	Value string
}

type Identity string

type DecryptRequest struct {
	EI EncryptedIdentity
}

type ActivationRequest struct {
	Identifier   string
	AsIdentifier string
}

type ActivationResponse struct {
	PP curve.Cryptogram
	PI curve.Cryptogram
}

// TransformRequest is the request object for the Transform operation from polymorphic identity/pseudonym to encrypted identity/pseudonym
// It contains the polymorphic identity or pseudonym and the ServiceProvider for which the transformation is intended
type TransformRequest struct {
	PI              PolymorphicIdentity
	PP              PolymorphicPseudonym
	ServiceProvider IServiceProvider
}

// TransformResponse is the response object for the Transform operation
// It contains the encrypted identity or pseudonym for the ServiceProvider
type TransformResponse struct {
	EI EncryptedIdentity
	EP EncryptedPseudonym
}

type EncryptedIdentity = curve.Cryptogram
type EncryptedPseudonym = curve.Cryptogram

type PolymorphicIdentity = curve.Cryptogram
type PolymorphicPseudonym = curve.Cryptogram

type Keys struct {
	// Y is the global Identity public key
	Y curve.PublicKey
	// Z is the global Pseudonym public key
	Z curve.PublicKey
	// Rekey is the re-encryption key specific to a ServiceProvider
	Rekey curve.Rekey
	// PrivateKey is the private key for a ServiceProvider
	PrivateKey curve.PrivateKey
	// Authentication provider Adherence Master key, meant for the Activation Service
	AAm curve.HMACKey
	// Authentication provider Adherence Derived key, meant for AuthProviders
	AAdi curve.HMACKey
}
