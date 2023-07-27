package verifier

import (

	"encoding/json"
	"math/big"
	"strconv"
	"encoding/binary"
	"github.com/ethereum/go-ethereum/crypto"

)

func fromRprBE(buff []byte) *big.Int {
	v := new(big.Int)
	for i := 0; i < len(buff)/4; i++ {
		b := buff[i*4 : (i+1)*4]
		num := binary.BigEndian.Uint32(b)
		v.Lsh(v, 32)
		v.Or(v, new(big.Int).SetUint64(uint64(num)))
	}
	return v
}

// hashToFr hashes the transcript using SHA3-256 and converts it to a big integer in the Fr field
func hashToFr(fq *big.Int,transcript []byte) *big.Int {
	hash := crypto.Keccak256(transcript)
	
	v := fromRprBE(hash)
	return v.Mod(v,fq)
}

func (g1 *G1) ToRprUncompressed(buff []byte, o int, p *G1) {
	if g1.IsZero(p.G) {
		buff[o] |= 0x40
		return
	}

	g1.F.ToRprBE(buff, o, p.G[0])
	g1.F.ToRprBE(buff, o+32, p.G[1])
	
}

func (fq *Fq) ToRprBE(buff []byte, o int, num *big.Int) {
	numBytes := num.Bytes()

	if len(numBytes) > 32 {
		
		num.Mod(num, fq.Q)
		numBytes = num.Bytes()
	}

	padding := 32 - len(numBytes)
	copy(buff[o+padding:], numBytes)
}

func calculateChallenges(proof *Proof, publicSignals []*big.Int) map[string]*big.Int {
	curve ,_:= NewBn128()
	G1 := curve.G1
	Fr := NewFq(curve.R)
	n8r:= 32
	transcript1 := make([]byte, len(publicSignals)*n8r+32*2*3)
	
	for i, signal := range publicSignals {
		Fr.ToRprBE(transcript1, i*n8r, signal)
	}
	
	G1.ToRprUncompressed(transcript1, len(publicSignals)*n8r+0, &proof.A)

	G1.ToRprUncompressed(transcript1, len(publicSignals)*n8r+32*2, &proof.B)
	
	
	G1.ToRprUncompressed(transcript1, len(publicSignals)*n8r+32*4, &proof.C)
	
	beta := hashToFr(Fr.Q,transcript1)
	
	transcript2 := make([]byte, n8r)
	Fr.ToRprBE(transcript2, 0, beta)
	gamma := hashToFr(Fr.Q,transcript2)

	transcript3 := make([]byte, 32*2)
	G1.ToRprUncompressed(transcript3, 0, &proof.Z)
	alpha := hashToFr(Fr.Q,transcript3)

	transcript4 := make([]byte, 32*2*3)
	G1.ToRprUncompressed(transcript4, 0, &proof.T1)
	G1.ToRprUncompressed(transcript4, 32*2, &proof.T2)
	G1.ToRprUncompressed(transcript4, 32*4, &proof.T3)
	xi := hashToFr(Fr.Q,transcript4)

	transcript5 := make([]byte, n8r*7)
	Fr.ToRprBE(transcript5, 0, proof.EvalA)
	Fr.ToRprBE(transcript5, n8r, proof.EvalB)
	Fr.ToRprBE(transcript5, n8r*2, proof.EvalC)
	Fr.ToRprBE(transcript5, n8r*3, proof.EvalS1)
	Fr.ToRprBE(transcript5, n8r*4, proof.EvalS2)
	Fr.ToRprBE(transcript5, n8r*5, proof.EvalZW)
	Fr.ToRprBE(transcript5, n8r*6, proof.EvalR)
	v := make([]*big.Int, 7)
	v[1] = hashToFr(Fr.Q, transcript5)
	for i := 2; i <= 6; i++ {
		v[i] = Fr.Mul(v[i-1], v[1])
	}

	transcript6 := make([]byte, 32*2*2)
	G1.ToRprUncompressed(transcript6, 0, &proof.Wxi)
	G1.ToRprUncompressed(transcript6, 32*2, &proof.Wxiw)
	u := hashToFr(Fr.Q,transcript6)

	challenges := map[string]*big.Int{
		"beta":  beta,
		"gamma": gamma,
		"alpha": alpha,
		"xi":    xi,
		"v1":    v[1],
		"v2":    v[2],
		"v3":    v[3],
		"v4":    v[4],
		"v5":    v[5],
		"v6":    v[6],
		"u":     u,
	}

	return challenges
}

type VkString struct {
	Protocol string   `json:"protocol"`
	Curve    string   `json:"curve"`
	NPublic  int      `json:"nPublic"`
	Power    int      `json:"power"`
	K1       string   `json:"k1"`
	K2       string   `json:"k2"`
	Qm       []string `json:"Qm"`
	Ql       []string `json:"Ql"`
	Qr       []string `json:"Qr"`
	Qo       []string `json:"Qo"`
	Qc       []string `json:"Qc"`
	S1       []string `json:"S1"`
	S2       []string `json:"S2"`
	S3       []string `json:"S3"`
	X2       [][]string `json:"X_2"`
	W        string   `json:"w"`
}

type ProofString struct {
	A       []string `json:"A"`
	B       []string `json:"B"`
	C       []string `json:"C"`
	Z       []string `json:"Z"`
	T1      []string `json:"T1"`
	T2      []string `json:"T2"`
	T3      []string `json:"T3"`
	EvalA   string    `json:"eval_a"`
	EvalB   string    `json:"eval_b"`
	EvalC   string    `json:"eval_c"`
	EvalS1  string    `json:"eval_s1"`
	EvalS2  string    `json:"eval_s2"`
	EvalZW  string    `json:"eval_zw"`
	EvalR   string    `json:"eval_r"`
	Wxi     []string `json:"Wxi"`
	Wxiw    []string `json:"Wxiw"`
	Protocol string    `json:"protocol"`
	Curve   string    `json:"curve"`
}

type Proof struct {
	A       G1
	B       G1
	C       G1
	Z      	G1 
	T1      G1
	T2      G1
	T3      G1
	EvalA   *big.Int
	EvalB   *big.Int
	EvalC   *big.Int
	EvalS1  *big.Int
	EvalS2  *big.Int
	EvalZW 	*big.Int
	EvalR   *big.Int
	Wxi     G1
	Wxiw    G1
}


type Vk struct {
	NPublic  int 
	Power    int      
	K1       int
	K2       int
	Qm       G1
	Ql       G1
	Qr       G1
	Qo       G1
	Qc       G1
	S1       G1
	S2       G1
	S3       G1
	X2       G2
	W        *big.Int
}

type Verifier struct {
	vk *Vk
	proof *Proof
	public []*big.Int
	challenges  map[string]*big.Int
	EvalLarange []*big.Int
	Pl *big.Int
	T *big.Int
	D G1
	F G1
	E G1
}

func ParseVk(vj []byte) (*Vk, error) {
	var vr VkString
	err := json.Unmarshal(vj, &vr)
	if err != nil {
		return nil, err
	}
	v, err := vkStringToVk(vr)
	return v, err
}
func ParseProof(pj []byte) (*Proof, error) {
	var pr ProofString
	err := json.Unmarshal(pj, &pr)
	if err != nil {
		return nil, err
	}
	p, err := ProofStringToProof(pr)
	return p, err
}

func ParsePub(dat []byte) ([]*big.Int,error) {
	var pub []string
	err := json.Unmarshal(dat, &pub)
	temp0, _:=new(big.Int).SetString(pub[0],10)
	temp1, _:=new(big.Int).SetString(pub[1],10)
	pub1 := []*big.Int{
		temp0,
		temp1,
	}
	
	return pub1 , err
}

func ProofStringToProof(pr ProofString) (*Proof,error) {
	var err error
	BN128, err := NewBn128()
	var p Proof
	p.A = StringToG1(BN128.Fq1,pr.A[0],pr.A[1])
	p.B = StringToG1(BN128.Fq1,pr.B[0],pr.B[1])
	p.C = StringToG1(BN128.Fq1,pr.C[0],pr.C[1])
	p.Z = StringToG1(BN128.Fq1,pr.Z[0],pr.Z[1])
	p.T1 = StringToG1(BN128.Fq1,pr.T1[0],pr.T1[1])
	p.T2 = StringToG1(BN128.Fq1,pr.T2[0],pr.T2[1])
	p.T3 = StringToG1(BN128.Fq1,pr.T3[0],pr.T3[1])
	p.Wxi = StringToG1(BN128.Fq1,pr.Wxi[0],pr.Wxi[1])
	p.Wxiw = StringToG1(BN128.Fq1,pr.Wxiw[0],pr.Wxiw[1])
	temp , _ := new(big.Int).SetString(pr.EvalA,10)
	p.EvalA = temp
	temp1 , _ := new(big.Int).SetString(pr.EvalB,10)
	p.EvalB = temp1
	temp2 , _ := new(big.Int).SetString(pr.EvalC,10)
	p.EvalC = temp2
	temp3 , _ := new(big.Int).SetString(pr.EvalR,10)
	p.EvalR = temp3
	temp4 , _ := new(big.Int).SetString(pr.EvalS1,10)
	p.EvalS1 = temp4
	temp5 , _ := new(big.Int).SetString(pr.EvalS2,10)
	p.EvalS2 = temp5
	temp6 , _ := new(big.Int).SetString(pr.EvalZW,10)
	p.EvalZW = temp6
	return &p, err
}

func vkStringToVk(vr VkString) (*Vk, error) {
	var err error
	BN128, err := NewBn128()
	
	var v Vk
	v.NPublic = vr.NPublic
	v.Power = vr.Power
	
	temp , err := strconv.Atoi(vr.K1)
	v.K1 = temp
	if err != nil {
		return nil, err
	}

	tempp , err := strconv.Atoi(vr.K2)
	v.K2 = tempp
	if err != nil {
		return nil, err
	}

	v.Qm = StringToG1( BN128.Fq1, vr.Qm[0],vr.Qm[1])
	v.Ql = StringToG1(BN128.Fq1, vr.Ql[0],vr.Ql[1])
	v.Qr = StringToG1(BN128.Fq1, vr.Qr[0],vr.Qr[1])
	v.Qo = StringToG1( BN128.Fq1, vr.Qo[0],vr.Qo[1])
	v.Qc = StringToG1( BN128.Fq1, vr.Qc[0],vr.Qc[1])
	v.S1 = StringToG1( BN128.Fq1, vr.S1[0],vr.S1[1])
	v.S2 = StringToG1( BN128.Fq1, vr.S2[0],vr.S2[1])
	v.S3 = StringToG1( BN128.Fq1, vr.S3[0],vr.S3[1])
	v.X2 = StringToG2( BN128.Fq2, vr.X2[0],vr.X2[1])
	
	temppp , _ := new(big.Int).SetString(vr.W,10)
	v.W = temppp
	return &v, err

}

func StringToG1( F Fq,x string, y string) (G1){
	temp0, _ := new(big.Int).SetString(x, 10)
	
	temp1, _ := new(big.Int).SetString(y,10)


	
	temp2 :=  NewG1(F, [2]*big.Int{
		temp0,
		temp1,
	})
	return temp2
}

func StringToG2(f Fq2, A1 []string, A0 []string) (G2){
	temp0, _ := new(big.Int).SetString(A1[0],10)
	temp1, _ := new(big.Int).SetString(A1[1],10)
	
	temp3, _ := new(big.Int).SetString(A0[0],10)

	temp4, _ := new(big.Int).SetString(A0[1],10)


	temp6 := NewG2(f,[2][2]*big.Int{
		{
			temp0, temp1,
		},
		{
			temp3,temp4,
		},
	})

	return temp6
}
func calculateNqr(half *big.Int, nqr *big.Int,Fr Fq) (*big.Int)  {
    r := Fr.Exp(nqr, half)

    negOne := Fr.Neg(big.NewInt(1))

    for r.Cmp(negOne) != 0 {
        nqr = Fr.Add(nqr, big.NewInt(1))
        r = Fr.Exp(nqr, half)
		
    }
	return nqr

}
func calculateSW(p *big.Int, one *big.Int, nqr *big.Int,Fr Fq) []*big.Int {
    s := 0
    t := new(big.Int).Sub(p, one)
	half := new(big.Int)
	half.Rsh(p,1)
	nqr = calculateNqr(half,nqr,Fr)
	
    for t.Bit(0) == 0 {
        s++
        t.Rsh(t, 1)
		
    }
	
    w := make([]*big.Int, s+1)
    w[s] = Fr.Exp(nqr, t)

    for i := s - 1; i >= 0; i-- {
        w[i] = Fr.Square(w[i+1])
        // w[i].Mod(w[i], p)
    }

    return w
}

func calculateLagrangeEvaluations( challenges map[string]*big.Int, vk *Vk) []*big.Int {
	curve,_ := NewBn128()
	Fr := NewFq(curve.R)

	xin,_ := challenges["xi"]
	
	domainSize := big.NewInt(1)

	for i := 0; i < vk.Power; i++ {
		xin = Fr.Square(xin)
		domainSize.Mul(domainSize, big.NewInt(2))
	}
	challenges["xin"] = xin

	challenges["zh"] = Fr.Sub(xin, big.NewInt(1))
	L := make([]*big.Int, vk.NPublic+1)
	
	n := new(big.Int).Mod(domainSize,Fr.Q)
	w := big.NewInt(1)
	W := calculateSW(Fr.Q, big.NewInt(1),big.NewInt(2),Fr)
	
	
	for i := 1; i <= max(1, vk.NPublic); i++ {
		L[i] = Fr.Div(
			Fr.Mul(w, challenges["zh"]),
			Fr.Mul(n, Fr.Sub(challenges["xi"], w)),
		)
		w = Fr.Mul(w, W[vk.Power])
	}

	return L
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func calculatePl(publicSignals []*big.Int, L []*big.Int) *big.Int {
	curve,_ := NewBn128()
	Fr := NewFq(curve.R)

    pl := Fr.Zero()
    for i := 0; i < len(publicSignals); i++ {
        w := publicSignals[i]
        pl = Fr.Sub(pl, Fr.Mul(w, L[i+1]))
    }

    return pl
}

func calculateT( proof *Proof, challenges  map[string]*big.Int, pl *big.Int, l1 *big.Int) *big.Int {
	curve,_ := NewBn128()
	Fr := NewFq(curve.R)

	
    num := new(big.Int).Set(proof.EvalR)
    num = num.Add(num, pl)
	
    e1 := new(big.Int).Set(proof.EvalA)
    e1 = Fr.Add(e1, Fr.Mul(challenges["beta"], proof.EvalS1))
    e1 = Fr.Add(e1, challenges["gamma"])

    e2 := new(big.Int).Set(proof.EvalB)
    e2 = Fr.Add(e2, Fr.Mul(challenges["beta"], proof.EvalS2))
    e2 = Fr.Add(e2, challenges["gamma"])

    e3 := new(big.Int).Set(proof.EvalC)
    e3 = Fr.Add(e3, challenges["gamma"])

    e := Fr.Mul(Fr.Mul(e1, e2), e3)
    e = Fr.Mul(e, proof.EvalZW)
    e = Fr.Mul(e, challenges["alpha"])

    num = Fr.Sub(num, e)

    num = Fr.Sub(num, Fr.Mul(l1, Fr.Square(challenges["alpha"])))

    t := Fr.Div(num, challenges["zh"])

    return t
}

func calculateD( proof *Proof, challenges map[string]*big.Int, vk *Vk, l1 *big.Int) G1 {
	curve,_ := NewBn128()
	Fr := NewFq(curve.R)
	var g1 G1
	g1.F = curve.Fq1
    s1 := Fr.Mul(Fr.Mul(proof.EvalA, proof.EvalB), challenges["v1"])
	
    res := g1.MulScalar(vk.Qm.G,s1)
	
    s2 := Fr.Mul(proof.EvalA, challenges["v1"])
    res = g1.Add(res, g1.MulScalar(vk.Ql.G, s2))
	
    s3 := Fr.Mul(proof.EvalB, challenges["v1"])
    res = g1.Add(res, g1.MulScalar(vk.Qr.G, s3))

    s4 := Fr.Mul(proof.EvalC, challenges["v1"])
    res = g1.Add(res, g1.MulScalar(vk.Qo.G, s4))

    res = g1.Add(res, g1.MulScalar(vk.Qc.G, challenges["v1"]))

    betaxi := Fr.Mul(challenges["beta"], challenges["xi"])
    s6a := proof.EvalA
    s6a = Fr.Add(s6a, betaxi)
    s6a = Fr.Add(s6a, challenges["gamma"])

    s6b := proof.EvalB
    s6b = Fr.Add(s6b, Fr.Mul(betaxi, big.NewInt(int64(vk.K1))))
    s6b = Fr.Add(s6b, challenges["gamma"])

    s6c := proof.EvalC
    s6c = Fr.Add(s6c, Fr.Mul(betaxi, big.NewInt(int64(vk.K2))))
    s6c = Fr.Add(s6c, challenges["gamma"])

    s6 := Fr.Mul(Fr.Mul(s6a, s6b), s6c)
    s6 = Fr.Mul(s6, Fr.Mul(challenges["alpha"], challenges["v1"]))

    s6d := Fr.Mul(Fr.Mul(l1, Fr.Square(challenges["alpha"])), challenges["v1"])
    s6 = Fr.Add(s6, s6d)

    s6 = Fr.Add(s6, challenges["u"])
    res = g1.Add(res, g1.MulScalar(proof.Z.G, s6))
	

    s7a := proof.EvalA
    s7a = Fr.Add(s7a, Fr.Mul(challenges["beta"], proof.EvalS1))
    s7a = Fr.Add(s7a, challenges["gamma"])

    s7b := proof.EvalB
    s7b = Fr.Add(s7b, Fr.Mul(challenges["beta"], proof.EvalS2))
    s7b = Fr.Add(s7b, challenges["gamma"])

    s7 := Fr.Mul(s7a, s7b)
    s7 = Fr.Mul(s7, challenges["alpha"])
    s7 = Fr.Mul(s7, challenges["v1"])
    s7 = Fr.Mul(s7, challenges["beta"])
    s7 = Fr.Mul(s7, proof.EvalZW)
    res = g1.Sub(res, g1.MulScalar(vk.S3.G, s7))
	res1 := G1{
		curve.Fq1,
		res,
	}
	// fmt.Println(g1.Affine(res))
    return res1
}

func calculateF(proof *Proof, challenges map[string]*big.Int, vk *Vk, D G1) G1 {
    curve,_ := NewBn128()
	Fr := NewFq(curve.R)
	var g1 G1
	g1.F = curve.Fq1
    res := proof.T1.G

    res = g1.Add(res, g1.MulScalar(proof.T2.G, challenges["xin"]))
    res = g1.Add(res, g1.MulScalar(proof.T3.G, Fr.Square(challenges["xin"])))
    res = g1.Add(res, D.G)
    res = g1.Add(res, g1.MulScalar(proof.A.G, challenges["v2"]))
    res = g1.Add(res, g1.MulScalar(proof.B.G, challenges["v3"]))
    res = g1.Add(res, g1.MulScalar(proof.C.G, challenges["v4"]))
    res = g1.Add(res, g1.MulScalar(vk.S1.G, challenges["v5"]))
    res = g1.Add(res, g1.MulScalar(vk.S2.G, challenges["v6"]))
	res1 := G1{
		curve.Fq1,
		res,
	}
	// fmt.Println(g1.Affine(res))
    return res1
}

func calculateE(proof *Proof, challenges map[string]*big.Int, t *big.Int) G1 {
	curve,_ := NewBn128()
	Fr := NewFq(curve.R)
	var g1 G1
	g1.F = curve.Fq1

    s := new(big.Int).Set(t)

    s = Fr.Add(s, Fr.Mul(challenges["v1"], proof.EvalR))
    s= Fr.Add(s, Fr.Mul(challenges["v2"], proof.EvalA))
    s= Fr.Add(s, Fr.Mul(challenges["v3"], proof.EvalB))
    s= Fr.Add(s, Fr.Mul(challenges["v4"], proof.EvalC))
    s= Fr.Add(s, Fr.Mul(challenges["v5"], proof.EvalS1))
    s= Fr.Add(s, Fr.Mul(challenges["v6"], proof.EvalS2))
    s= Fr.Add(s, Fr.Mul(challenges["u"], proof.EvalZW))

    res := g1.MulScalar(curve.G1.G, s)
	res1 := G1{
		curve.Fq1,
		res,
	}
	
	// fmt.Println(g1.Affine(res))
    return res1
}

func verify(proof *Proof, challenges map[string]*big.Int,vk *Vk, E, F G1) (bool) {
	curve,_ := NewBn128()
	Fr := NewFq(curve.R)
	var g1 G1
	g1.F = curve.Fq1
	A1 := proof.Wxi.G
	A1 = g1.Add(A1, g1.MulScalar(proof.Wxiw.G, challenges["u"]))

	B1 := g1.MulScalar(proof.Wxi.G, challenges["xi"])
	W := calculateSW(Fr.Q, big.NewInt(1),big.NewInt(2),Fr)
	s := Fr.Mul(Fr.Mul(challenges["u"], challenges["xi"]), W[vk.Power])
	B1 = g1.Add(B1, g1.MulScalar(proof.Wxiw.G, s))
	B1 = g1.Add(B1,F.G)
	B1 = g1.Add(B1,g1.Neg(E.G))
	if !curve.Fq12.Equal(curve.Pairing(A1,vk.X2.G),curve.Pairing(B1,curve.G2.G)) {
		
		return false
	}
	
	return true
}

func  NewVerifier(vk *Vk, proof *Proof, public []*big.Int) ( *Verifier) {
	verifier := &Verifier{
		vk : vk,
		proof : proof,
		public : public,
	
	}
	verifier.challenges = calculateChallenges(verifier.proof,verifier.public)
	verifier.EvalLarange = calculateLagrangeEvaluations(verifier.challenges,verifier.vk)
	verifier.Pl = calculatePl(public, verifier.EvalLarange)
	verifier.T = calculateT(verifier.proof,verifier.challenges,verifier.Pl,verifier.EvalLarange[1])
	verifier.D = calculateD(verifier.proof,verifier.challenges,verifier.vk,verifier.EvalLarange[1])
	verifier.E = calculateE(verifier.proof,verifier.challenges,verifier.T)
	verifier.F = calculateF(verifier.proof,verifier.challenges,verifier.vk,verifier.D)
	return verifier
}

func (verifier *Verifier) Verify() (bool){
	res := verify(verifier.proof,verifier.challenges,verifier.vk,verifier.E,verifier.F)
	return res
}