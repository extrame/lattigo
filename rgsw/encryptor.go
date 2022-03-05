package rgsw

import (
	"github.com/tuneinsight/lattigo/v3/ring"
	"github.com/tuneinsight/lattigo/v3/rlwe"
	"github.com/tuneinsight/lattigo/v3/utils"
	"math/big"
)

// Encryptor a generic RLWE encryption interface.
type Encryptor interface {
	Encrypt(pt *rlwe.Plaintext, ct *Ciphertext)
	ShallowCopy() Encryptor
	WithKey(key interface{}) Encryptor
}

type encryptor struct {
	*encryptorBase
	*encryptorSamplers
	*encryptorBuffers
	basisextender *ring.BasisExtender
}

type skEncryptor struct {
	encryptor
	sk *rlwe.SecretKey
}

// NewEncryptor creates a new Encryptor
// Accepts either a secret-key or a public-key.
func NewEncryptor(params rlwe.Parameters, key interface{}) Encryptor {
	enc := newEncryptor(params)
	return enc.setKey(key)
}

func newEncryptor(params rlwe.Parameters) encryptor {

	var bc *ring.BasisExtender
	if params.PCount() != 0 {
		bc = ring.NewBasisExtender(params.RingQ(), params.RingP())
	}

	return encryptor{
		encryptorBase:     newEncryptorBase(params),
		encryptorSamplers: newEncryptorSamplers(params),
		encryptorBuffers:  newEncryptorBuffers(params),
		basisextender:     bc,
	}
}

// encryptorBase is a struct used to encrypt Plaintexts. It stores the public-key and/or secret-key.
type encryptorBase struct {
	params rlwe.Parameters
}

func newEncryptorBase(params rlwe.Parameters) *encryptorBase {
	return &encryptorBase{params}
}

type encryptorSamplers struct {
	gaussianSampler *ring.GaussianSampler
	ternarySampler  *ring.TernarySampler
	uniformSamplerQ *ring.UniformSampler
	uniformSamplerP *ring.UniformSampler
}

func newEncryptorSamplers(params rlwe.Parameters) *encryptorSamplers {
	prng, err := utils.NewPRNG()
	if err != nil {
		panic(err)
	}

	var uniformSamplerP *ring.UniformSampler
	if params.PCount() != 0 {
		uniformSamplerP = ring.NewUniformSampler(prng, params.RingP())
	}

	return &encryptorSamplers{
		gaussianSampler: ring.NewGaussianSampler(prng, params.RingQ(), params.Sigma(), int(6*params.Sigma())),
		ternarySampler:  ring.NewTernarySamplerWithHammingWeight(prng, params.RingQ(), params.HammingWeight(), false),
		uniformSamplerQ: ring.NewUniformSampler(prng, params.RingQ()),
		uniformSamplerP: uniformSamplerP,
	}
}

type encryptorBuffers struct {
	poolQ [2]*ring.Poly
	poolP [3]*ring.Poly
}

func newEncryptorBuffers(params rlwe.Parameters) *encryptorBuffers {

	ringQ := params.RingQ()
	ringP := params.RingP()

	var poolP [3]*ring.Poly
	if params.PCount() != 0 {
		poolP = [3]*ring.Poly{ringP.NewPoly(), ringP.NewPoly(), ringP.NewPoly()}
	}

	return &encryptorBuffers{
		poolQ: [2]*ring.Poly{ringQ.NewPoly(), ringQ.NewPoly()},
		poolP: poolP,
	}
}

// ShallowCopy creates a shallow copy of this skEncryptor in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Encryptors can be used concurrently.
func (enc *skEncryptor) ShallowCopy() Encryptor {
	return &skEncryptor{*enc.encryptor.ShallowCopy(), enc.sk}
}

// ShallowCopy creates a shallow copy of this encryptor in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Encryptors can be used concurrently.
func (enc *encryptor) ShallowCopy() *encryptor {

	var bc *ring.BasisExtender
	if enc.params.PCount() != 0 {
		bc = enc.basisextender.ShallowCopy()
	}

	return &encryptor{
		encryptorBase:     enc.encryptorBase,
		encryptorSamplers: newEncryptorSamplers(enc.params),
		encryptorBuffers:  newEncryptorBuffers(enc.params),
		basisextender:     bc,
	}
}

// WithKey creates a shallow copy of this encryptor with a new key in which all the read-only data-structures are
// shared with the receiver and the temporary buffers are reallocated. The receiver and the returned
// Encryptors can be used concurrently.
func (enc *encryptor) WithKey(key interface{}) Encryptor {
	return enc.ShallowCopy().setKey(key)
}

func (enc *encryptor) setKey(key interface{}) Encryptor {
	switch key := key.(type) {
	case *rlwe.SecretKey:
		if key.Value.Q.Degree() != enc.params.N() {
			panic("cannot setKey: sk ring degree does not match params ring degree")
		}
		return &skEncryptor{*enc, key}
	default:
		panic("cannot setKey: key must be *rlwe.SecretKey")
	}
}

func (enc *skEncryptor) Encrypt(plaintext *rlwe.Plaintext, ciphertext *Ciphertext) {

	params := enc.params
	ringQ := params.RingQ()
	ringQP := params.RingQP()
	isNTT := ciphertext.Value[0][0][0][0].Q.IsNTT
	levelQ := ciphertext.LevelQ()
	levelP := ciphertext.LevelP()

	decompRNS := params.DecompRNS(levelQ, levelP)
	decompBIT := params.DecompBIT(levelQ, levelP)

	ptTimesP := enc.poolQ[1]

	if plaintext != nil {
		if levelP != -1 {
			var pBigInt *big.Int
			if levelP == params.PCount()-1 {
				pBigInt = params.RingP().ModulusBigint
			} else {
				P := params.RingP().Modulus
				pBigInt = new(big.Int).SetUint64(P[0])
				for i := 1; i < levelP+1; i++ {
					pBigInt.Mul(pBigInt, ring.NewUint(P[i]))
				}
			}

			ringQ.MulScalarBigintLvl(levelQ, plaintext.Value, pBigInt, ptTimesP)
			if !plaintext.Value.IsNTT {
				ringQ.NTTLvl(levelQ, ptTimesP, ptTimesP)
			}

		} else {
			levelP = 0
			if !plaintext.Value.IsNTT {
				ringQ.NTTLvl(levelQ, plaintext.Value, ptTimesP)
			} else {
				ring.CopyLvl(levelQ, plaintext.Value, ptTimesP)
			}
		}
	}

	var index int
	for j := 0; j < decompBIT; j++ {
		for i := 0; i < decompRNS; i++ {

			enc.encryptZeroSymetricQP(levelQ, levelP, enc.sk.Value, true, isNTT, ciphertext.Value[i][j][0][0], ciphertext.Value[i][j][0][1])
			enc.encryptZeroSymetricQP(levelQ, levelP, enc.sk.Value, true, isNTT, ciphertext.Value[i][j][1][0], ciphertext.Value[i][j][1][1])

			if plaintext != nil {
				for k := 0; k < levelP+1; k++ {

					index = i*(levelP+1) + k

					// It handles the case where nb pj does not divide nb qi
					if index >= levelQ+1 {
						break
					}

					qi := ringQ.Modulus[index]
					p0tmp := ptTimesP.Coeffs[index]
					p1tmp := ciphertext.Value[i][j][0][0].Q.Coeffs[index]
					p2tmp := ciphertext.Value[i][j][1][1].Q.Coeffs[index]

					for w := 0; w < ringQ.N; w++ {
						p1tmp[w] = ring.CRed(p1tmp[w]+p0tmp[w], qi)
						p2tmp[w] = ring.CRed(p2tmp[w]+p0tmp[w], qi)
					}
				}
			}

			ringQP.MFormLvl(levelQ, levelP, ciphertext.Value[i][j][0][0], ciphertext.Value[i][j][0][0])
			ringQP.MFormLvl(levelQ, levelP, ciphertext.Value[i][j][0][1], ciphertext.Value[i][j][0][1])
			ringQP.MFormLvl(levelQ, levelP, ciphertext.Value[i][j][1][0], ciphertext.Value[i][j][1][0])
			ringQP.MFormLvl(levelQ, levelP, ciphertext.Value[i][j][1][1], ciphertext.Value[i][j][1][1])
		}

		ringQ.MulScalar(ptTimesP, 1<<params.LogBase2(), ptTimesP)
	}
}

func (enc *encryptor) encryptZeroSymetricQP(levelQ, levelP int, sk rlwe.PolyQP, sample, ntt bool, a, b rlwe.PolyQP) {

	params := enc.params
	ringQP := params.RingQP()

	hasModulusP := a.P != nil && b.P != nil

	if ntt {
		enc.gaussianSampler.ReadLvl(levelQ, a.Q)

		if hasModulusP {
			ringQP.ExtendBasisSmallNormAndCenter(a.Q, levelP, nil, a.P)
		}

		ringQP.NTTLvl(levelQ, levelP, a, a)
	}

	if sample {
		enc.uniformSamplerQ.ReadLvl(levelQ, b.Q)

		if hasModulusP {
			enc.uniformSamplerP.ReadLvl(levelP, b.P)
		}
	}

	ringQP.MulCoeffsMontgomeryAndSubLvl(levelQ, levelP, b, sk, a)

	if !ntt {
		ringQP.InvNTTLvl(levelQ, levelP, a, a)
		ringQP.InvNTTLvl(levelQ, levelP, b, b)

		e := rlwe.PolyQP{Q: enc.poolQ[0], P: enc.poolP[0]}
		enc.gaussianSampler.ReadLvl(levelQ, e.Q)

		if hasModulusP {
			ringQP.ExtendBasisSmallNormAndCenter(e.Q, levelP, nil, e.P)
		}

		ringQP.AddLvl(levelQ, levelP, a, e, a)
	}
}
