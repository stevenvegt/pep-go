package pepgo

import "github.com/stevenvegt/pep-go/curve"

type IServiceProvider interface {
	DecryptEI(DecryptRequest) (Identity, error)
	GetRekey() curve.Rekey
	IKMARegisterable
}

type ServiceProvider struct {
	identifier string
	keys       Keys
}

func (sp ServiceProvider) GetIdentifier() string {
	return sp.identifier
}

func (sp ServiceProvider) DecryptEI(req DecryptRequest) (Identity, error) {
	m, err := curve.Decrypt(sp.keys.PrivateKey, req.EI)
	if err != nil {
		return "", err
	}
	return Identity(m), nil
}

func (sp *ServiceProvider) SetKeys(keys Keys) {
	sp.keys = keys
}

func (sp ServiceProvider) GetRekey() curve.Rekey {
	return sp.keys.Rekey
}

func NewServiceProvider(id string) IServiceProvider {
	return &ServiceProvider{identifier: id}
}
