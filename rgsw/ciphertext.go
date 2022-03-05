package rgsw

import (
	"github.com/tuneinsight/lattigo/v3/rlwe"
)

// RGSWCiphertext is a generic type for RGSW ciphertext.
type Ciphertext struct {
	Value [][][2][2]rlwe.PolyQP
}

// LevelQ returns the level of the modulus Q of the target.
func (ct *Ciphertext) LevelQ() int {
	return ct.Value[0][0][0][0].Q.Level()
}

// LevelP returns the level of the modulus P of the target.
func (ct *Ciphertext) LevelP() int {
	if ct.Value[0][0][0][0].P != nil {
		return ct.Value[0][0][0][0].P.Level()
	}
	return -1
}

// NewCiphertextNTT allocates a new RGSW ciphertext in the NTT domain.
func NewCiphertextNTT(params rlwe.Parameters, levelQ int) (ct *Ciphertext) {

	ct = new(Ciphertext)
	ringQP := params.RingQP()
	levelP := params.PCount() - 1
	decompRNS := params.DecompRNS(levelQ, levelP)
	decompBIT := params.DecompBIT(levelQ, levelP)
	ct.Value = make([][][2][2]rlwe.PolyQP, decompRNS)
	for i := 0; i < decompRNS; i++ {
		ct.Value[i] = make([][2][2]rlwe.PolyQP, decompBIT)
		for j := 0; j < decompBIT; j++ {

			ct.Value[i][j][0] = [2]rlwe.PolyQP{ringQP.NewPolyLvl(levelQ, levelP), ringQP.NewPolyLvl(levelQ, levelP)}
			ct.Value[i][j][1] = [2]rlwe.PolyQP{ringQP.NewPolyLvl(levelQ, levelP), ringQP.NewPolyLvl(levelQ, levelP)}

			ct.Value[i][j][0][0].Q.IsNTT = true
			ct.Value[i][j][1][0].Q.IsNTT = true

			if levelP != -1 {
				ct.Value[i][j][0][0].P.IsNTT = true
				ct.Value[i][j][1][0].P.IsNTT = true
			}
		}
	}
	return
}
