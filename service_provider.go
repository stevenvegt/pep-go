package pepgo

import "github.com/stevenvegt/pep-go/curve"

type IServiceProvider interface {
	DecryptEI(DecryptRequest) (Identity, error)
	GetRekey() curve.Rekey
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
	m, err := curve.Decrypt(sp.Keys.PrivateKey, req.EI)
	if err != nil {
		return "", err
	}
	return Identity(m), nil
}

func (sp *ServiceProvider) SetKeys(keys Keys) {
	sp.Keys = keys
}

func (sp ServiceProvider) GetRekey() curve.Rekey {
	return sp.Keys.Rekey
}

func NewServiceProvider(id string) IServiceProvider {
	return &ServiceProvider{Identifier: id}
}
