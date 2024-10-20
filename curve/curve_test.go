// write test cases for the ristretto.go file

package curve

import (
	"testing"
)

func TestKetGen(t *testing.T) {
	kp := KeyGen()
	if kp.PublicKey.X.IsNonZeroI() != 1 {
		t.Errorf("Public key is not generated properly")
	}

	if kp.PublicKey.Y.IsNonZeroI() != 1 {
		t.Errorf("Public key is not generated properly")
	}

	if kp.PrivateKey.IsNonZeroI() != 1 {
		t.Errorf("Private key is not generated properly")
	}
}
