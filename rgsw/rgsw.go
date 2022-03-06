package rgsw

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"math"
)

// Evaluator is a struct storing the necessary elements to perform
// homomorphic operations with RGSW ciphertexts.
type Evaluator struct {
	*rlwe.KeySwitcher
}

// NewEvaluator creates a new evaluator.
func NewEvaluator(params rlwe.Parameters) *Evaluator {
	return &Evaluator{rlwe.NewKeySwitcher(params)}
}

// ExternalProduct computes RLWE x RGSW -> RLWE
// RLWE : (-as + m + e, a)
//  x
// RGSW : [(-as + P*w*m1 + e, a), (-bs + e, b + P*w*m1)]
//  =
// RLWE : (<RLWE, RGSW[0]>, <RLWE, RGSW[1]>)
func (eval *Evaluator) ExternalProduct(op0 *rlwe.Ciphertext, op1 *Ciphertext, op2 *rlwe.Ciphertext) {

	levelQ, levelP := op1.LevelQ(), op1.LevelP()

	var c0QP, c1QP rlwe.PolyQP
	if op0 == op2 {
		c0QP, c1QP = eval.Pool[1], eval.Pool[2]
	} else {
		c0QP, c1QP = rlwe.PolyQP{Q: op2.Value[0], P: eval.Pool[1].P}, rlwe.PolyQP{Q: op2.Value[1], P: eval.Pool[2].P}
	}

	if levelP < 1 {

		// If log(Q) * (Q-1)**2 < 2^{64}-1
		if ringQ := eval.RingQ(); levelQ == 0 && (ringQ.Modulus[0]>>29) == 0 {
			eval.externalProduct32Bit(op0, op1, c0QP.Q, c1QP.Q)
			q, mredParams := ringQ.Modulus[0], ringQ.MredParams[0]
			ring.InvMFormVec(c0QP.Q.Coeffs[0], op2.Value[0].Coeffs[0], q, mredParams)
			ring.InvMFormVec(c1QP.Q.Coeffs[0], op2.Value[1].Coeffs[0], q, mredParams)
		} else {
			eval.externalProductInPlaceSinglePAndBitDecomp(op0, op1, eval.Pool[1], eval.Pool[2])

			if levelP == 0 {
				eval.BasisExtender.ModDownQPtoQNTT(levelQ, levelP, c0QP.Q, c0QP.P, op2.Value[0])
				eval.BasisExtender.ModDownQPtoQNTT(levelQ, levelP, c1QP.Q, c1QP.P, op2.Value[1])
			} else {
				op2.Value[0].CopyValues(c0QP.Q)
				op2.Value[1].CopyValues(c1QP.Q)
			}
		}
	} else {
		eval.externalProductInPlaceMultipleP(levelQ, levelP, op0, op1, eval.Pool[1].Q, eval.Pool[1].P, eval.Pool[2].Q, eval.Pool[2].P)
		eval.BasisExtender.ModDownQPtoQNTT(levelQ, levelP, c0QP.Q, c0QP.P, op2.Value[0])
		eval.BasisExtender.ModDownQPtoQNTT(levelQ, levelP, c1QP.Q, c1QP.P, op2.Value[1])
	}
}

func (eval *Evaluator) externalProduct32Bit(ct0 *rlwe.Ciphertext, rgsw *Ciphertext, c0, c1 *ring.Poly) {

	// rgsw = [(-as + P*w*m1 + e, a), (-bs + e, b + P*w*m1)]
	// ct = [-cs + m0 + e, c]
	// ctOut = [<ct, rgsw[0]>, <ct, rgsw[1]>] = [ct[0] * rgsw[0][0] + ct[1] * rgsw[0][1], ct[0] * rgsw[1][0] + ct[1] * rgsw[1][1]]
	ringQ := eval.RingQ()
	lb2 := eval.LogBase2()
	mask := uint64(((1 << lb2) - 1))

	cw := eval.Pool[0].Q.Coeffs[0]
	cwNTT := eval.PoolBitDecomp

	acc0 := c0.Coeffs[0]
	acc1 := c1.Coeffs[0]

	// (a, b) + (c0 * rgsw[0][0], c0 * rgsw[0][1])
	ringQ.InvNTTLvl(0, ct0.Value[0], eval.PoolInvNTT)
	for j, el := range rgsw.Value[0] {
		ring.MaskVec(eval.PoolInvNTT.Coeffs[0], cw, j*lb2, mask)
		if j == 0 {
			ringQ.NTTSingleLazy(0, cw, cwNTT)
			ring.MulCoeffsNoModVec(el[0][0].Q.Coeffs[0], cwNTT, acc0)
			ring.MulCoeffsNoModVec(el[0][1].Q.Coeffs[0], cwNTT, acc1)
		} else {
			ringQ.NTTSingleLazy(0, cw, cwNTT)
			ring.MulCoeffsNoModAndAddNoModVec(el[0][0].Q.Coeffs[0], cwNTT, acc0)
			ring.MulCoeffsNoModAndAddNoModVec(el[0][1].Q.Coeffs[0], cwNTT, acc1)
		}
	}

	// (a, b) + (c1 * rgsw[1][0], c1 * rgsw[1][1])
	ringQ.InvNTTLvl(0, ct0.Value[1], eval.PoolInvNTT)
	for j, el := range rgsw.Value[0] {
		ring.MaskVec(eval.PoolInvNTT.Coeffs[0], cw, j*lb2, mask)
		ringQ.NTTSingleLazy(0, cw, cwNTT)
		ring.MulCoeffsNoModAndAddNoModVec(el[1][0].Q.Coeffs[0], cwNTT, acc0)
		ring.MulCoeffsNoModAndAddNoModVec(el[1][1].Q.Coeffs[0], cwNTT, acc1)
	}
}

func (eval *Evaluator) externalProductInPlaceSinglePAndBitDecomp(ct0 *rlwe.Ciphertext, rgsw *Ciphertext, c0QP, c1QP rlwe.PolyQP) {

	// rgsw = [(-as + P*w*m1 + e, a), (-bs + e, b + P*w*m1)]
	// ct = [-cs + m0 + e, c]
	// ctOut = [<ct, rgsw[0]>, <ct, rgsw[1]>] = [ct[0] * rgsw[0][0] + ct[1] * rgsw[0][1], ct[0] * rgsw[1][0] + ct[1] * rgsw[1][1]]
	ringQ := eval.RingQ()
	ringP := eval.RingP()

	levelQ := rgsw.LevelQ()
	levelP := rgsw.LevelP()

	lb2 := eval.LogBase2()
	mask := uint64(((1 << lb2) - 1))
	if mask == 0 {
		mask = 0xFFFFFFFFFFFFFFFF
	}

	decompRNS := eval.DecompRNS(levelQ, levelP)
	decompBIT := eval.DecompBIT(levelQ, levelP)

	ringQ.InvNTTLvl(levelQ, ct0.Value[0], eval.PoolInvNTT)
	cw := eval.Pool[0].Q.Coeffs[0]
	cwNTT := eval.PoolBitDecomp
	for i := 0; i < decompRNS; i++ {
		for j := 0; j < decompBIT; j++ {

			ring.MaskVec(eval.PoolInvNTT.Coeffs[i], cw, j*lb2, mask)

			// (a, b) + (c0 * rgsw[0][0], c0 * rgsw[0][1])
			if i == 0 && j == 0 {
				for u := 0; u < levelQ+1; u++ {
					ringQ.NTTSingleLazy(u, cw, cwNTT)
					ring.MulCoeffsMontgomeryVec(rgsw.Value[i][j][0][0].Q.Coeffs[u], cwNTT, c0QP.Q.Coeffs[u], ringQ.Modulus[u], ringQ.MredParams[u])
					ring.MulCoeffsMontgomeryVec(rgsw.Value[i][j][0][1].Q.Coeffs[u], cwNTT, c1QP.Q.Coeffs[u], ringQ.Modulus[u], ringQ.MredParams[u])
				}

				for u := 0; u < levelP+1; u++ {
					ringP.NTTSingleLazy(u, cw, cwNTT)
					ring.MulCoeffsMontgomeryVec(rgsw.Value[i][j][0][0].P.Coeffs[u], cwNTT, c0QP.P.Coeffs[u], ringP.Modulus[u], ringP.MredParams[u])
					ring.MulCoeffsMontgomeryVec(rgsw.Value[i][j][0][1].P.Coeffs[u], cwNTT, c1QP.P.Coeffs[u], ringP.Modulus[u], ringP.MredParams[u])
				}
			} else {
				for u := 0; u < levelQ+1; u++ {
					ringQ.NTTSingleLazy(u, cw, cwNTT)
					ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][0][0].Q.Coeffs[u], cwNTT, c0QP.Q.Coeffs[u], ringQ.Modulus[u], ringQ.MredParams[u])
					ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][0][1].Q.Coeffs[u], cwNTT, c1QP.Q.Coeffs[u], ringQ.Modulus[u], ringQ.MredParams[u])
				}

				for u := 0; u < levelP+1; u++ {
					ringP.NTTSingleLazy(u, cw, cwNTT)
					ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][0][0].P.Coeffs[u], cwNTT, c0QP.P.Coeffs[u], ringP.Modulus[u], ringP.MredParams[u])
					ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][0][1].P.Coeffs[u], cwNTT, c1QP.P.Coeffs[u], ringP.Modulus[u], ringP.MredParams[u])
				}
			}
		}
	}

	ringQ.InvNTTLvl(levelQ, ct0.Value[1], eval.PoolInvNTT)
	for i := 0; i < decompRNS; i++ {
		for j := 0; j < decompBIT; j++ {
			ring.MaskVec(eval.PoolInvNTT.Coeffs[i], cw, j*lb2, mask)

			// (a, b) + (c1 * rgsw[1][0], c1 * rgsw[1][1])

			for u := 0; u < levelQ+1; u++ {
				ringQ.NTTSingleLazy(u, cw, cwNTT)
				ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][1][0].Q.Coeffs[u], cwNTT, c0QP.Q.Coeffs[u], ringQ.Modulus[u], ringQ.MredParams[u])
				ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][1][1].Q.Coeffs[u], cwNTT, c1QP.Q.Coeffs[u], ringQ.Modulus[u], ringQ.MredParams[u])
			}

			for u := 0; u < levelP+1; u++ {
				ringP.NTTSingleLazy(u, cw, cwNTT)
				ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][1][0].P.Coeffs[u], cwNTT, c0QP.P.Coeffs[u], ringP.Modulus[u], ringP.MredParams[u])
				ring.MulCoeffsMontgomeryAndAddVec(rgsw.Value[i][j][1][1].P.Coeffs[u], cwNTT, c1QP.P.Coeffs[u], ringP.Modulus[u], ringP.MredParams[u])
			}
		}
	}
}

func (eval *Evaluator) externalProductInPlaceMultipleP(levelQ, levelP int, ct0 *rlwe.Ciphertext, rgsw *Ciphertext, c0OutQ, c0OutP, c1OutQ, c1OutP *ring.Poly) {
	var reduce int

	ringQ := eval.RingQ()
	ringP := eval.RingP()
	ringQP := eval.RingQP()

	c2QP := eval.Pool[0]

	c0QP := rlwe.PolyQP{Q: c0OutQ, P: c0OutP}
	c1QP := rlwe.PolyQP{Q: c1OutQ, P: c1OutP}

	alpha := levelP + 1
	beta := int(math.Ceil(float64(levelQ+1) / float64(levelP+1)))

	QiOverF := eval.Parameters.QiOverflowMargin(levelQ) >> 1
	PiOverF := eval.Parameters.PiOverflowMargin(levelP) >> 1

	var c2NTT, c2InvNTT *ring.Poly
	if ct0.Value[0].IsNTT {
		c2NTT = ct0.Value[0]
		c2InvNTT = eval.PoolInvNTT
		ringQ.InvNTTLvl(levelQ, c2NTT, c2InvNTT)
	} else {
		c2NTT = eval.PoolInvNTT
		c2InvNTT = ct0.Value[0]
		ringQ.NTTLvl(levelQ, c2InvNTT, c2NTT)
	}

	// (a, b) + (c0 * rgsw[0][0], c0 * rgsw[0][1])
	for i := 0; i < beta; i++ {

		eval.DecomposeSingleNTT(levelQ, levelP, alpha, i, c2NTT, c2InvNTT, c2QP.Q, c2QP.P)

		if i == 0 {
			ringQP.MulCoeffsMontgomeryConstantLvl(levelQ, levelP, rgsw.Value[i][0][0][0], c2QP, c0QP)
			ringQP.MulCoeffsMontgomeryConstantLvl(levelQ, levelP, rgsw.Value[i][0][0][1], c2QP, c1QP)
		} else {
			ringQP.MulCoeffsMontgomeryConstantAndAddNoModLvl(levelQ, levelP, rgsw.Value[i][0][0][0], c2QP, c0QP)
			ringQP.MulCoeffsMontgomeryConstantAndAddNoModLvl(levelQ, levelP, rgsw.Value[i][0][0][1], c2QP, c1QP)
		}

		if reduce%QiOverF == QiOverF-1 {
			ringQ.ReduceLvl(levelQ, c0QP.Q, c0QP.Q)
			ringQ.ReduceLvl(levelQ, c1QP.Q, c1QP.Q)
		}

		if reduce%PiOverF == PiOverF-1 {
			ringP.ReduceLvl(levelP, c0QP.P, c0QP.P)
			ringP.ReduceLvl(levelP, c1QP.P, c1QP.P)
		}

		reduce++
	}

	if ct0.Value[0].IsNTT {
		c2NTT = ct0.Value[1]
		c2InvNTT = eval.PoolInvNTT
		ringQ.InvNTTLvl(levelQ, c2NTT, c2InvNTT)
	} else {
		c2NTT = eval.PoolInvNTT
		c2InvNTT = ct0.Value[1]
		ringQ.NTTLvl(levelQ, c2InvNTT, c2NTT)
	}

	// (a, b) + (c1 * rgsw[1][0], c1 * rgsw[1][1])
	for i := 0; i < beta; i++ {

		eval.DecomposeSingleNTT(levelQ, levelP, alpha, i, c2NTT, c2InvNTT, c2QP.Q, c2QP.P)

		if i == 0 {
			ringQP.MulCoeffsMontgomeryConstantAndAddNoModLvl(levelQ, levelP, rgsw.Value[i][0][1][0], c2QP, c0QP)
			ringQP.MulCoeffsMontgomeryConstantAndAddNoModLvl(levelQ, levelP, rgsw.Value[i][0][1][1], c2QP, c1QP)
		} else {
			ringQP.MulCoeffsMontgomeryConstantAndAddNoModLvl(levelQ, levelP, rgsw.Value[i][0][1][0], c2QP, c0QP)
			ringQP.MulCoeffsMontgomeryConstantAndAddNoModLvl(levelQ, levelP, rgsw.Value[i][0][1][1], c2QP, c1QP)
		}

		if reduce%QiOverF == QiOverF-1 {
			ringQ.ReduceLvl(levelQ, c0QP.Q, c0QP.Q)
			ringQ.ReduceLvl(levelQ, c1QP.Q, c1QP.Q)
		}

		if reduce%PiOverF == PiOverF-1 {
			ringP.ReduceLvl(levelP, c0QP.P, c0QP.P)
			ringP.ReduceLvl(levelP, c1QP.P, c1QP.P)
		}

		reduce++
	}

	if reduce%QiOverF != 0 {
		ringQ.ReduceLvl(levelQ, c0QP.Q, c0QP.Q)
		ringQ.ReduceLvl(levelQ, c1QP.Q, c1QP.Q)
	}

	if reduce%PiOverF != 0 {
		ringP.ReduceLvl(levelP, c0QP.P, c0QP.P)
		ringP.ReduceLvl(levelP, c1QP.P, c1QP.P)
	}
}
