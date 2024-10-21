package main

import (
	"log"

	pepgo "github.com/stevenvegt/pep-go"
)

func main() {
	// The following code snippet demonstrates how apply PEP to create a polymorphic identity for
	// an AuthenticationProvider and transform it to an encrypted identity for a ServiceProvider
	// and decrypt it back to the original identity.

	// Setup:
	kma := pepgo.NewKeyManagementAuthority()

	as := pepgo.NewActivationService()
	ap := pepgo.NewAuthProvider("AP1")
	sp := pepgo.NewServiceProvider("SP1")

	kma.RegisterActivationService(as)
	kma.RegisterAuthProvider(ap)
	kma.RegisterServiceProvider(sp)

	identifier := "BSN1234"
	log.Println("identifier: ", identifier)

	// Activate BSN to a polymorphic identity
	activationResp, err := as.Activate(pepgo.ActivationRequest{
		Identifier: identifier,
		APid:       ap.GetIdentifier(),
	})
	if err != nil {
		log.Fatal("could not activate:", err)
	}

	log.Println("cryptogram after activation: ", activationResp.PI)
	// Transform the polymorphic identity to an encrypted identity for the ServiceProvider
	transformResp, err := ap.Transform(pepgo.TransformRequest{
		PI:         activationResp.PI,
		SPIdentity: sp.GetIdentifier(),
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Println("cryptogram after transform:  ", transformResp.EI)

	// Decrypt the encrypted identity back to the original BSN
	decryptedIdentity, err := sp.DecryptEI(pepgo.DecryptRequest{EI: transformResp.EI})
	if err != nil {
		log.Fatal("could not decrypt:", err)
	}
	log.Println("decrypted msg: ", decryptedIdentity)
}
