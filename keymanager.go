package pepgo

import "github.com/stevenvegt/pep-go/curve"

func NewKeyManagementAuthority() IKeyManagementAuthority {
	aam := curve.HMACKey{}
	aam.Rand()
	return KeyManagementAuthority{
		keys:             Keys{AAm: aam},
		authProviders:    make(map[string]IKMARegisterable),
		serviceProviders: make(map[string]IKMARegisterable),
		yPair:            curve.KeyGen(),
		zPair:            curve.KeyGen(),
	}
}

func (kma KeyManagementAuthority) RegisterActivationService(as IKMARegisterable) {
	keys := Keys{Y: kma.yPair.PublicKey, Z: kma.zPair.PublicKey, AAm: kma.keys.AAm}
	as.SetKeys(keys)
}

func (kma KeyManagementAuthority) RegisterAuthProvider(ap IKMARegisterable) {
	kma.authProviders[ap.GetIdentifier()] = ap
	aadi := calcDerivedKey(kma.keys.AAm, ap.GetIdentifier())
	keys := Keys{Y: kma.yPair.PublicKey, Z: kma.zPair.PublicKey, AAdi: aadi}
	ap.SetKeys(keys)
}

func (kma KeyManagementAuthority) RegisterServiceProvider(sp IKMARegisterable) {
	kma.serviceProviders[sp.GetIdentifier()] = sp
	var rekey curve.Rekey
	rekey.Rand()
	privKey := curve.MultiplyKey(kma.yPair.PrivateKey, rekey)
	keys := Keys{Y: kma.yPair.PublicKey, Z: kma.zPair.PublicKey, Rekey: rekey, PrivateKey: privKey}
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
	authProviders    map[string]IKMARegisterable
	serviceProviders map[string]IKMARegisterable
	keys             Keys
	// yPair is the global Identity key pair
	yPair curve.KeyPair
	// zPair is the global Pseudonym key pair
	zPair curve.KeyPair
}
