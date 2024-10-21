package pepgo

import (
	"log"

	"github.com/stevenvegt/pep-go/curve"
)

type ServiceProviderKeys struct {
	// Y is an ElGamal public key called Identity Private Public ServiceProviderKeys
	Y curve.PublicKey
	// Z is an ElGamal public key called Pseudonym Private Public ServiceProviderKeys
	Z curve.PublicKey

	// IDdi is an EC private key (ElGamal decryption) called Identity Decryption Derived key.
	IDdi curve.PrivateKey

	// IDpi is the EC public key corresponding to IDDi called Identity Decryption Public key
	IDpi curve.PublicKey
}

type IServiceProvider interface {
	DecryptEI(DecryptRequest) (Identity, error)
	SetKeys(ServiceProviderKeys)
	GetPublicKey() curve.PublicKey
	IIdentifiable
}

type ServiceProvider struct {
	identifier string
	keys       ServiceProviderKeys
}

func (sp ServiceProvider) GetIdentifier() string {
	return sp.identifier
}

// DecryptEI performs alidation and decryption by service provider SPid of Encrypted Identity EI.
func (sp ServiceProvider) DecryptEI(req DecryptRequest) (Identity, error) {
	log.Println("OP: DecryptEI")
	c := curve.Cryptogram{A: req.EI.A, B: req.EI.B, C: sp.keys.IDpi}
	m, err := curve.Decrypt(sp.keys.IDdi, c)
	if err != nil {
		return "", err
	}
	return Identity(m), nil
}

func (sp *ServiceProvider) SetKeys(keys ServiceProviderKeys) {
	sp.keys = keys
}

func (sp ServiceProvider) GetPublicKey() curve.PublicKey {
	return sp.keys.IDpi
}

func NewServiceProvider(id string) IServiceProvider {
	return &ServiceProvider{identifier: id}
}
