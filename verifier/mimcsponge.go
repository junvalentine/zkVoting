package verifier

import (
	"math/big"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/iden3/go-iden3-crypto/ff"
)

const (
	SEED     = "mimcsponge"
	NROUNDS  = 220
)

type MimcSponge struct {
	cts []*ff.Element
}

func NewMimcSponge() *MimcSponge {
	return &MimcSponge{
		cts: getConstants(SEED, NROUNDS),
	}
}


func getConstants(seed string, nRounds int) []*ff.Element {
	if seed == "" {
		seed = SEED
	}
	if nRounds == 0 {
		nRounds = NROUNDS
	}
	cts := make([]*ff.Element, nRounds)
	c := crypto.Keccak256([]byte(SEED))
	for i := 1; i < nRounds; i++ {
		c = crypto.Keccak256(c)
		cts[i] = ff.NewElement().SetBigInt(new(big.Int).SetBytes(c))
	}
	cts[0] = ff.NewElement().SetZero()
	cts[len(cts)-1] = ff.NewElement().SetZero()
	return cts
}

func (ms *MimcSponge) Hash(xLIn, xRIn, kIn *ff.Element) (*ff.Element, *ff.Element) {
	
	xL := *xLIn
	xR := *xRIn
	k := *kIn

	for i := 0; i < NROUNDS; i++ {
		c := ms.cts[i]
		var t *ff.Element
		if i == 0 {
			t = ff.NewElement().Add(&xL, &k)
		} else {
			t = ff.NewElement().Add(ff.NewElement().Add(&xL, &k), c)
		}
		t2 := ff.NewElement().Square(t)
		t4 := ff.NewElement().Square(t2)
		t5 := ff.NewElement().Mul(t4, t)
		xRTmp := xR
		if i < (NROUNDS - 1) {
			xR = xL
			xL = *ff.NewElement().Add(&xRTmp, t5)
		} else {
			xR = *ff.NewElement().Add(&xRTmp, t5)
		}
	}
	return &xL, &xR
}

func (ms *MimcSponge) MultiHash(arr []*big.Int, key *ff.Element,numOutputs int) ([]*big.Int, error) {
	new_arr := make([]*ff.Element,0,len(arr))
	for i:=0 ; i< len(arr); i++{
		new_arr = append(new_arr, ff.NewElement().SetBigInt(arr[i]))
	}
	if numOutputs == 0 {
		numOutputs = 1
	}
	if key == nil {
		key = ff.NewElement().SetZero()
	}

	R := ff.NewElement().SetZero()
	C := ff.NewElement().SetZero()

	for i := 0; i < len(arr); i++ {
		R = ff.NewElement().Add(R, new_arr[i])
		SxL, SxR := ms.Hash(R, C, key)
		R = SxL
		C = SxR
	}
	outputs := []*ff.Element{R}
	for i := 1; i < numOutputs; i++ {
		SxL, SxR := ms.Hash(R, C, key)
		R = SxL
		C = SxR
		outputs = append(outputs, R)
	}
	if len(outputs) == 1 {
		res := big.NewInt(0)
		outputs[0].ToBigIntRegular(res)
		return []*big.Int{res} , nil
	} else {
		res := make([]*big.Int,0,len(outputs))
		for i:= 0; i < len(outputs); i++ {
			temp := big.NewInt(0)
			res = append(res, outputs[i].ToBigIntRegular(temp))
		}
		return res, nil
	}
	
	
}
