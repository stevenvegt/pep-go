package main

import (
	"crypto/hmac"
	"crypto/sha256"
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
	Identifier   string
	ASIdentifier string
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

func calcDerivedKey(key ristretto.HMACKey, identifier string) ristretto.HMACKey {
	log.Printf("calclDerivedKey, id: %s, key: %x\n", identifier, key)
	mac := hmac.New(sha256.New, key.Bytes())
	mac.Write([]byte(identifier))
	sum := mac.Sum(nil)
	dk := ristretto.HMACKey{}
	dk.SetBytes(sum)
	return dk
}

func (as ActivationService) Activate(req ActivationRequest) (ActivationResponse, error) {
	p := ristretto.Embed([]byte(req.Identifier))

	aaid := calcDerivedKey(as.Keys.AAm, req.ASIdentifier)
	log.Println("aaid: ", aaid)

	p = ristretto.Unshuffle(p, aaid)

	c, err := ristretto.Encrypt(as.Keys.Y, p)
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

	res := ristretto.Rerandomize(req.PI.Cryptogram, ap.Keys.Y)

	// "decrypt" the polymorphic Identifier for this ServiceProvider
	res = ristretto.Reshuffle(res, ap.Keys.AAdi)
	log.Println("aaid: ", ap.Keys.AAdi)

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
	// Authentication provider Adherence Master key, meant for the Activation Service
	AAm ristretto.HMACKey
	// Authentication provider Adherence Derived key, meant for AuthProviders
	AAdi ristretto.HMACKey
}

func NewKeyManagementAuthority() IKeyManagementAuthority {
	aam := ristretto.HMACKey{}
	aam.Rand()
	return KeyManagementAuthority{
		keys:             Keys{AAm: aam},
		AuthProviders:    make(map[string]IKMARegisterable),
		ServiceProviders: make(map[string]IKMARegisterable),
		YPair:            ristretto.KeyGen(),
		ZPair:            ristretto.KeyGen(),
	}
}

func (kma KeyManagementAuthority) RegisterActivationService(as IKMARegisterable) {
	keys := Keys{Y: kma.YPair.PublicKey, Z: kma.ZPair.PublicKey, AAm: kma.keys.AAm}
	as.SetKeys(keys)
}

func (kma KeyManagementAuthority) RegisterAuthProvider(ap IKMARegisterable) {
	kma.AuthProviders[ap.GetIdentifier()] = ap
	aadi := calcDerivedKey(kma.keys.AAm, ap.GetIdentifier())
	keys := Keys{Y: kma.YPair.PublicKey, Z: kma.ZPair.PublicKey, AAdi: aadi}
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
		Identifier:   identifier,
		ASIdentifier: ap.GetIdentifier(),
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
