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
	Identifier string
	APid       string
}

type ActivationResponse struct {
	PP curve.Cryptogram
	PI curve.Cryptogram
}

// TransformRequest is the request object for the Transform operation from polymorphic identity/pseudonym to encrypted identity/pseudonym
// It contains the polymorphic identity or pseudonym and the ServiceProvider for which the transformation is intended
type TransformRequest struct {
	PI         PolymorphicIdentity
	PP         PolymorphicPseudonym
	SPIdentity string
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
