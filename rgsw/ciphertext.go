package rgsw

import (
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

// Ciphertext is a generic type for RGSW ciphertext.
type Ciphertext struct {
	Value [2]rlwe.SwitchingKey
}

// LevelQ returns the level of the modulus Q of the target.
func (ct *Ciphertext) LevelQ() int {
	return ct.Value[0].Value[0][0][0].Q.Level()
}

// LevelP returns the level of the modulus P of the target.
func (ct *Ciphertext) LevelP() int {
	if ct.Value[0].Value[0][0][0].P != nil {
		return ct.Value[0].Value[0][0][0].P.Level()
	}
	return -1
}

// NewCiphertextNTT allocates a new RGSW ciphertext in the NTT domain.
func NewCiphertextNTT(params rlwe.Parameters, levelQ int) (ct *Ciphertext) {
	return &Ciphertext{
		Value: [2]rlwe.SwitchingKey{
			*rlwe.NewSwitchingKey(params, levelQ, params.PCount()-1),
			*rlwe.NewSwitchingKey(params, levelQ, params.PCount()-1),
		},
	}
}
