package main

import (
	"log"

	"github.com/stevenvegt/pep-go/ristretto"
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
}

type ActivationResponse struct {
	PP ristretto.Cryptogram
}

// IActivationService is an interface for the activation service
// The activation service create polymorphic pseudonyms and identities for the BSN for AuthProviders
type IActivationService interface {
	Activate(ActivationRequest) (ActivationResponse, error)
	IKMARegisterable
}

type ActivationService struct {
	Keys Keys
}

func NewActivationService() IActivationService {
	return &ActivationService{}
}

func (as ActivationService) Activate(req ActivationRequest) (ActivationResponse, error) {
	c, err := ristretto.Encrypt(as.Keys.Y, []byte(req.Identifier))
	if err != nil {
		return ActivationResponse{}, err
	}
	return ActivationResponse{
		PP: c,
	}, nil

}

func (as ActivationService) GetIdentifier() string {
	return "AS1"
}

func (as *ActivationService) SetKeys(keys Keys) {
	as.Keys = keys
}

// IAuthProvider is an interface for the AuthProvider.
// An AuthProvider is responsible for transforming the polymorphic identify or pseudonym into an encrypted identity or pseudonym for specific ServiceProviders
// It is not able to decrypt the BSN itself
type IAuthProvider interface {
	Transform(TransformRequest) (TransformResponse, error)
	IKMARegisterable
}

type TransformRequest struct {
	PI              EncryptedIdentity
	ServiceProvider IServiceProvider
}

type TransformResponse struct {
	EP EncryptedIdentity
}

type EncryptedIdentity struct {
	ristretto.Cryptogram
}

type AuthProvider struct {
	Identifier string
	Keys       Keys
}

func NewAuthProvider(id string) IAuthProvider {
	return &AuthProvider{Identifier: id}
}

func (ap AuthProvider) Transform(req TransformRequest) (TransformResponse, error) {
	// res := ristretto.Reshuffle(req.PP.Cryptogram)
	res := ristretto.Rerandomize(req.PI.Cryptogram, ap.Keys.Y)

	res = ristretto.ReKey(res, req.ServiceProvider.GetRekey())
	return TransformResponse{
		EP: EncryptedIdentity{res},
	}, nil
}

func (ap AuthProvider) GetIdentifier() string {
	return ap.Identifier
}

func (ap *AuthProvider) SetKeys(keys Keys) {
	ap.Keys = keys
}

type IKeyManagementAuthority interface {
	RegisterAuthProvider(IKMARegisterable)
	RegisterServiceProvider(IKMARegisterable)
	RegisterActivationService(IKMARegisterable)
}

type KeyManagementAuthority struct {
	AuthProviders    map[string]IKMARegisterable
	ServiceProviders map[string]IKMARegisterable
	keys             Keys
	// YPair is the global Identity key pair
	YPair ristretto.KeyPair
	// ZPair is the global Pseudonym key pair
	ZPair ristretto.KeyPair
}

type Keys struct {
	// Y is the global Identity public key
	Y ristretto.PublicKey
	// Z is the global Pseudonym public key
	Z ristretto.PublicKey
	// Rekey is the re-encryption key specific to a ServiceProvider
	Rekey ristretto.Rekey
	// PrivateKey is the private key for a ServiceProvider
	PrivateKey ristretto.PrivateKey
}

func NewKeyManagementAuthority() IKeyManagementAuthority {
	return KeyManagementAuthority{
		AuthProviders:    make(map[string]IKMARegisterable),
		ServiceProviders: make(map[string]IKMARegisterable),
		YPair:            ristretto.KeyGen(),
		ZPair:            ristretto.KeyGen(),
	}
}

func (kma KeyManagementAuthority) RegisterActivationService(as IKMARegisterable) {
	keys := Keys{Y: kma.YPair.PublicKey, Z: kma.ZPair.PublicKey}
	as.SetKeys(keys)
}

func (kma KeyManagementAuthority) RegisterAuthProvider(ap IKMARegisterable) {
	kma.AuthProviders[ap.GetIdentifier()] = ap
	keys := Keys{Y: kma.YPair.PublicKey, Z: kma.ZPair.PublicKey}
	ap.SetKeys(keys)
}

func (kma KeyManagementAuthority) RegisterServiceProvider(sp IKMARegisterable) {
	kma.ServiceProviders[sp.GetIdentifier()] = sp
	var rekey ristretto.Rekey
	rekey.Rand()
	privKey := ristretto.MultiplyKey(kma.YPair.PrivateKey, rekey)
	keys := Keys{Y: kma.YPair.PublicKey, Z: kma.ZPair.PublicKey, Rekey: rekey, PrivateKey: privKey}
	sp.SetKeys(keys)
}

type IKMARegisterable interface {
	GetIdentifier() string
	SetKeys(Keys)
}

type IServiceProvider interface {
	DecryptEI(DecryptRequest) (Identity, error)
	GetRekey() ristretto.Rekey
	IKMARegisterable
}

type ServiceProvider struct {
	Identifier string
	Keys       Keys
}

func (sp ServiceProvider) GetIdentifier() string {
	return sp.Identifier
}

func (sp ServiceProvider) DecryptEI(req DecryptRequest) (Identity, error) {
	m, err := ristretto.Decrypt(sp.Keys.PrivateKey, req.EI.Cryptogram)
	if err != nil {
		return "", err
	}
	return Identity(m), nil
}

func (sp *ServiceProvider) SetKeys(keys Keys) {
	sp.Keys = keys
}

func (sp ServiceProvider) GetRekey() ristretto.Rekey {
	return sp.Keys.Rekey
}

func NewServiceProvider(id string) IServiceProvider {
	return &ServiceProvider{Identifier: id}
}

func main() {

	// Setup:
	kma := NewKeyManagementAuthority()

	as := NewActivationService()
	ap := NewAuthProvider("AP1")
	sp := NewServiceProvider("SP1")

	kma.RegisterActivationService(as)
	kma.RegisterAuthProvider(ap)
	kma.RegisterServiceProvider(sp)

	identifier := "BSN1234"
	log.Println("identifier: ", identifier)

	// Activate BSN
	activationResp, err := as.Activate(ActivationRequest{
		Identifier: identifier,
	})
	if err != nil {
		log.Fatal("could not activate:", err)
	}

	log.Println("cryptogram after activation: ", activationResp.PP)
	//
	transformResp, err := ap.Transform(TransformRequest{PI: EncryptedIdentity{activationResp.PP}, ServiceProvider: sp})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("cryptogram after transform:  ", transformResp.EP.Cryptogram)

	decryptedIdentity, err := sp.DecryptEI(DecryptRequest{EI: EncryptedIdentity{transformResp.EP.Cryptogram}})
	if err != nil {
		log.Fatal("could not decrypt:", err)
	}
	//
	log.Println("decrypted msg: ", decryptedIdentity)
}
