package pepgo

import (
	"log"

	"github.com/stevenvegt/pep-go/curve"
)

type KMAKeys struct {
	YPair curve.KeyPair
	ZPair curve.KeyPair
	// IEm Identity Encryption Master key
	// Used for PI to EI transformation, Global key used by APs
	IEm curve.HMACKey
	// AAm Authentication provider Adherence Master key
	// Used to make PP/PI AuthProvider specific, Global key, used by Activation Service
	AAm curve.HMACKey
}

func NewKeyManagementAuthority() IKeyManagementAuthority {
	IEm := curve.HMACKey{}
	IEm.Rand()
	AAm := curve.HMACKey{}
	AAm.Rand()
	return KeyManagementAuthority{
		authProviders:    make(map[string]IAuthProvider),
		serviceProviders: make(map[string]IServiceProvider),
		keys: KMAKeys{
			YPair: curve.KeyGen(),
			ZPair: curve.KeyGen(),
			IEm:   IEm,
			AAm:   AAm,
		},
	}
}

func (kma KeyManagementAuthority) RegisterActivationService(as IActivationService) {
	keys := ActivationServiceKeys{
		Y:   kma.keys.YPair.PublicKey,
		Z:   kma.keys.ZPair.PublicKey,
		AAm: kma.keys.AAm,
	}
	as.SetKeys(keys)
}

type IIdentifiable interface {
	GetIdentifier() string
}

func (kma KeyManagementAuthority) RegisterAuthProvider(ap IAuthProvider) {
	log.Println("OP: RegisterAuthProvider")
	kma.authProviders[ap.GetIdentifier()] = ap
	aadi := calcDerivedKey(kma.keys.AAm, []byte(ap.GetIdentifier()))
	// keys := Keys{Y: kma.yPair.PublicKey, Z: kma.zPair.PublicKey, AAdi: aadi}
	keys := AuthProviderKeys{
		Y:    kma.keys.YPair.PublicKey,
		AAdi: aadi,
		IEm:  kma.keys.IEm,
	}

	ap.SetKeys(keys)
}

func (kma KeyManagementAuthority) RegisterServiceProvider(sp IServiceProvider) {
	log.Println("OP: RegisterServiceProvider")

	kma.serviceProviders[sp.GetIdentifier()] = sp

	IEdi := calcDerivedKey(kma.keys.IEm, []byte(sp.GetIdentifier()))
	IDdi := curve.MultiplyKey(kma.keys.YPair.PrivateKey, IEdi.Scalar())
	IDpi := curve.DerivePubKey(IDdi)

	keys := ServiceProviderKeys{
		Y:    kma.keys.YPair.PublicKey,
		Z:    kma.keys.ZPair.PublicKey,
		IDdi: IDdi,
		IDpi: IDpi,
	}
	sp.SetKeys(keys)
}

type IIdentifiabe interface {
	GetIdentifier() string
}

type IKeyManagementAuthority interface {
	RegisterAuthProvider(IAuthProvider)
	RegisterServiceProvider(IServiceProvider)
	RegisterActivationService(IActivationService)
}

type KeyManagementAuthority struct {
	authProviders    map[string]IAuthProvider
	serviceProviders map[string]IServiceProvider
	keys             KMAKeys
}
