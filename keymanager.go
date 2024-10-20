package pepgo

import "github.com/stevenvegt/pep-go/curve"

func NewKeyManagementAuthority() IKeyManagementAuthority {
	aam := curve.HMACKey{}
	aam.Rand()
	return KeyManagementAuthority{
		keys:             Keys{AAm: aam},
		AuthProviders:    make(map[string]IKMARegisterable),
		ServiceProviders: make(map[string]IKMARegisterable),
		YPair:            curve.KeyGen(),
		ZPair:            curve.KeyGen(),
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
	var rekey curve.Rekey
	rekey.Rand()
	privKey := curve.MultiplyKey(kma.YPair.PrivateKey, rekey)
	keys := Keys{Y: kma.YPair.PublicKey, Z: kma.ZPair.PublicKey, Rekey: rekey, PrivateKey: privKey}
	sp.SetKeys(keys)
}

type IKMARegisterable interface {
	GetIdentifier() string
	SetKeys(Keys)
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
	YPair curve.KeyPair
	// ZPair is the global Pseudonym key pair
	ZPair curve.KeyPair
}
