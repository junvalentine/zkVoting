package main

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"github.com/tendermint/tendermint/abci/example/code"
	abcitypes "github.com/tendermint/tendermint/abci/types"
	"github.com/tendermint/tendermint/version"
	"time"
	"crypto/sha256"
	"bytes"
	"zkvoting/verifier"
)

const (
	CodeTypeOK            		uint32 = 0
	CodeTypeError 				uint32 = 1
)

var (
	AppVersion uint64 = 0x1
)

type PData struct{
	Proof 	verifier.ProofString	`json:"proof"`
	Public 	[]string 	`json:"public"`
}

type AData struct{
	Vkey	  verifier.VkString	`json:"vkey"`
	Cand 	  Candidate `json:"cand"`
	RegStart  int64		`json:"regstart"`
	RegEnd	  int64		`json:"regend"`
	VoteStart int64		`json:"votestart"`
	VoteEnd	  int64		`json:"voteend"`
}

type Trans struct{
	Type	string 		`json:"type"`
	Vdata	Verify		`json:"vdata"`
	Pdata	PData		`json:"pdata"`
	Adata   AData 		`json:"adata"`
}

type Candidate struct{
	Name 	[]string	`json:"name"`
	Vote 	[]int64		`json:"vote"`
}

//------------------------------------------------------------

var _ abcitypes.Application = (*DApplication)(nil)

type DApplication struct {
	abcitypes.BaseApplication
	zktree 			*verifier.ZkTree 			// voter merkle tree
	candidate 		map[string]int64 	// candidate list
	isVoted 		map[string]int 		// check voter
	isUsed 			map[string]int 		// check Dg15.pubkey
	leafNode 		[]string 			// zktree leaves
	voterid 		int 				// number of voter
	voteid			int					// vote index
	verifyKey 		*verifier.Vk 				// verification key
	vkeyHash 		[32]byte 			// hash of verification key
	height 			int64				// current height of chain
	zkroot		 	[]byte				// current root of zktree
	regStart 		int64 				// register start
	regEnd 			int64				// register end
	voteStart 		int64 				// vote start
	voteEnd			int64 				// vote end
}

func NewDApplication(vKey []byte) *DApplication {
	vkey1 := bytes.ReplaceAll(vKey, []byte{32}, []byte(""))
	vkey2 := bytes.ReplaceAll(vkey1, []byte{10}, []byte(""))
	hash := sha256.Sum256(vkey2)
	zktree, err := verifier.NewZkTree(20, []*big.Int{})
	if err != nil {
		panic(err)
	}
	return &DApplication{zktree: zktree, vkeyHash: hash, regStart: 9999999999999, voteStart: 9999999999999, height:0}
}

func (app *DApplication) Info(req abcitypes.RequestInfo) abcitypes.ResponseInfo {
	return abcitypes.ResponseInfo{
		Data:             fmt.Sprintf("Zkvoting"),
		Version:          version.ABCIVersion,
		AppVersion:       AppVersion,
		LastBlockHeight:  app.height,
		LastBlockAppHash: app.zkroot,	
	}
}

func (DApplication) SetOption(req abcitypes.RequestSetOption) abcitypes.ResponseSetOption {
	return abcitypes.ResponseSetOption{}
}

func (app *DApplication) isValid(tx []byte) (code uint32) {
	var trans Trans
	err := json.Unmarshal(tx,&trans)
	if err != nil {
		return 1
	}
	if trans.Type == "vote" {
		// check trans.Pdata
		data := trans.Pdata
		proof,public := data.Proof,data.Public

		proof1, err := json.Marshal(proof)
		if err != nil {
			return 1
		}

		public1, err := json.Marshal(public)
		if err != nil {
			return 1
		}

		_,err = verifier.ParseProof(proof1)
		if err != nil {
			return 1
		}

		_,err = verifier.ParsePub(public1)
		if err != nil{
			return 1
		}
	} else if trans.Type == "register" {
		// check trans.Vdata
		verify := trans.Vdata

		verify1, err := json.Marshal(verify)
		if err != nil {
			return 1
		}

		_, err = ParseVerify(verify1)
		if err != nil {
			return 1
		}
	} else if trans.Type == "admin"{
		
	} else {
		return 1
	}
	return 0
} 

func (app *DApplication) CheckTx(req abcitypes.RequestCheckTx) abcitypes.ResponseCheckTx {
	code := app.isValid(req.Tx)

	return abcitypes.ResponseCheckTx{Code: code, GasWanted: 1}
}

func (app *DApplication) DeliverTx(req abcitypes.RequestDeliverTx) abcitypes.ResponseDeliverTx {
	var trans Trans
	err := json.Unmarshal(req.Tx,&trans)
	var events []abcitypes.Event

	if (trans.Type == "vote"){
		// check if in vote period
		now := time.Now()
		vtime := now.Unix()
		if vtime < app.voteStart || vtime > app.voteEnd{
			panic("Not in the voting period")
		} 
		// verify(comm,pub)
		data := trans.Pdata
		proof, public := data.Proof,data.Public
		proof1, _ := json.Marshal(proof)
		if err != nil {
			panic(err)
		}
		public1, err := json.Marshal(public)
		if err != nil {
			panic(err)
		}
		pr, err := verifier.ParseProof(proof1)
		if err != nil {
			panic(err)
		}
		pub, err := verifier.ParsePub(public1)
		if err != nil {
			panic(err)
		}
		//check if candidate exist or not?
		name := string(pub[0].Bytes())
		if _, ok := app.candidate[name]; !ok {
			panic("Candidate not found")
		}
		verifier1 := verifier.NewVerifier(app.verifyKey,pr,pub)
		verify := verifier1.Verify()

		if (verify == false) {
			panic("Verification failed")
		}else if(app.isVoted[pub[1].String()] != 0){
			panic("This voter has already voted")
		}else{
			// set isVoted for voter's hash(k)
			app.isVoted[pub[1].String()] = 1
			// add vote to candidate
			app.candidate[name] += 1
		}

		// Event
		events = []abcitypes.Event{
			{
				Type: "vote",
				Attributes: []abcitypes.EventAttribute{
					//TODO
					{Key: []byte("candidate"), Value: []byte(name), Index: false},
					{Key: []byte("nullifier hash"), Value: []byte(pub[1].String()), Index: false},
					{Key: []byte("time"), Value: []byte(strconv.FormatInt(vtime,10)), Index: true},
				},
			},
		}
	} else if trans.Type == "register"{
		// check if in register period
		now := time.Now()
		rtime := now.Unix()
		fmt.Println(rtime)
		fmt.Println(app.regEnd)
		fmt.Println(app.regStart)
		if rtime < app.regStart || rtime > app.regEnd {
			panic("Not in the register period")
		}

		// v1 = verify(DG15,SOD,CA)
		// v2 = verify(authData,aaSig,DG15)
		verify := trans.Vdata
		verify1, err := json.Marshal(verify)
		if err != nil {
			panic(err)
		}
		ver, err := ParseVerify(verify1)
		if err != nil {
			panic(err)
		}
		
		tmp := v1_verify(ver.Dg15, ver.Sod)
		if tmp == false{
			panic("Tampered Chip")
		}
		tmp = v2_verify(ver.H, ver.AaSig, ver.Dg15)
		if tmp == false{
			panic("Cloning Chip")
		}

 		// pass verification, insert hash to zktree
		if (app.isUsed[ver.Dg15] != 0){
			panic("This pubkey has already used")
		}else{
			// insert h to zktree and set isUsed
			hash := new(big.Int)
			_, err := hash.SetString(ver.H,16)
			if !err {
				panic(err)
			}
			app.zktree.QuickInsert(hash)
			app.isUsed[ver.Dg15] = 1

			// append node to list of leaves
			app.leafNode = append(app.leafNode,hash.String())
			
			// Events
			events = []abcitypes.Event{
				{
					Type: "register",
					Attributes: []abcitypes.EventAttribute{
						{Key: []byte("voter id"), Value: []byte(strconv.Itoa(app.voterid)), Index: true},
						{Key: []byte("hash"), Value: []byte(ver.H), Index: false},
						{Key: []byte("time"), Value: []byte(strconv.FormatInt(rtime,10)), Index: false},
					},
				},
			}
			app.voterid += 1
		}
	} else if trans.Type == "admin"{
		// time
		now := time.Now()
		atime := now.Unix()
		
		// get data
		data := trans.Adata
		vkey, cand := data.Vkey, data.Cand
		vkey1, _ := json.Marshal(vkey)

		// verify admin
		hash := sha256.Sum256(vkey1)

		if hash != app.vkeyHash {
			panic("Admin verification failed")
		}

		// reset zktree and zkroot, leafNode, id
		app.zktree, err = verifier.NewZkTree(20, []*big.Int{})
		if err != nil {
			panic(err)
		}
		app.zkroot = nil
		app.leafNode = nil
		app.voterid = 0

		// parse time
		app.regStart, app.regEnd = data.RegStart, data.RegEnd
		app.voteStart, app.voteEnd = data.VoteStart, data.VoteEnd
		
		// parse vkey
		app.verifyKey, _ = verifier.ParseVk(vkey1)
		
		// parse candidate list
		app.candidate = make(map[string]int64)
		for i, name := range cand.Name {
			app.candidate[name] = cand.Vote[i]
		}
		
		// reset isUsed and isVoted
		app.isUsed = make(map[string]int)
		app.isVoted = make(map[string]int)

		events = []abcitypes.Event{
			{
				Type: "admin",
				Attributes: []abcitypes.EventAttribute{
					{Key: []byte("vote id"), Value: []byte(strconv.Itoa(app.voteid)), Index: true},
					{Key: []byte("regstart"), Value: []byte(strconv.FormatInt(app.regStart,10)), Index: false},
					{Key: []byte("regend"), Value: []byte(strconv.FormatInt(app.regEnd,10)), Index: false},
					{Key: []byte("votestart"), Value: []byte(strconv.FormatInt(app.voteStart,10)), Index: false},
					{Key: []byte("voteend"), Value: []byte(strconv.FormatInt(app.voteEnd,10)), Index: false},
					{Key: []byte("time"), Value: []byte(strconv.FormatInt(atime,10)), Index: false},
				},
			},
		}
		app.voteid += 1
	}
	return abcitypes.ResponseDeliverTx{Code: code.CodeTypeOK, Events: events}
}

func (app *DApplication) Commit() abcitypes.ResponseCommit {
	app.height++
	num := app.zktree.GetRoot()
	app.zkroot = []byte(num.Text(16))
	return abcitypes.ResponseCommit{}
}

// Returns an associated value or nil if missing.
func (app *DApplication) Query(reqQuery abcitypes.RequestQuery) (resQuery abcitypes.ResponseQuery) {
	switch reqQuery.Path{
		// root of merkle tree
		case "root":
			num := app.zktree.GetRoot()
			resQuery.Key = []byte("Root")
			resQuery.Value = []byte(num.Text(16))

		// total vote
		case "total":
			var sum int64
			sum = 0  
			for _, votes := range app.candidate {
				sum += votes
			}
			resQuery.Key = []byte("Total vote")
			resQuery.Value = []byte(fmt.Sprint(sum))

		// number of votes of 1 candidate
		case "candidate1":
			name := string(reqQuery.Data)
			if _, ok := app.candidate[name]; ok {
				resQuery.Key = []byte("Vote count")
				resQuery.Value = []byte(fmt.Sprint(app.candidate[name]))
				resQuery.Log = "Candidate found"
			} else {
				resQuery.Log = "Candidate not found"
			}

		// show candidate list
		case "candidates":
			var list []string
			for name, _ := range app.candidate{
				list = append(list,name)
			}
			data := map[string]interface{}{
				"candidates": list,
			}
			resQuery.Value, _ = json.Marshal(data)

		// show the candidate - vote list
		case "getResult":
			var canlist []string
			var numlist []int64
			for name, num := range app.candidate{
				canlist = append(canlist,name)
				numlist = append(numlist,num)
			}
			data := map[string]interface{}{
				"candidates": canlist,
				"voteCounts": numlist,
			}
			resQuery.Value, _ = json.Marshal(data)

		// get leaf of zktree
		case "getMerkleTree":
			data := map[string]interface{}{
				"merkleTree": app.leafNode,
			}
			resQuery.Value, _ = json.Marshal(data)

		// show path given an element
		// case "path":
		// 	hash := new(big.Int)
		// 	_, err := hash.SetString(string(reqQuery.Data),16)
		// 	if !err {
		// 		resQuery.Log = "Convert to big number failed"
		// 		break
		// 	}
		// 	// Debug
		// 	// index := app.zktree.indexOf(hash)
		// 	// tmp:= map[string] interface{}{
		// 	// 	"index" : index,
		// 	// 	"hash" : hash,
		// 	// }
		// 	// tmp1, _ := json.Marshal(tmp)
		// 	ele, ind, _ := app.zktree.Path(app.zktree.IndexOf(hash))
		// 	elej, _ := json.Marshal(ele)
		// 	indj, _ := json.Marshal(ind)
		// 	result := make(map[string]json.RawMessage)
		// 	result["pathElements"] = json.RawMessage(elej)
		// 	result["pathIndices"] = json.RawMessage(indj)	
		// 	// result["index"] = json.RawMessage(tmp1)
		// 	resQuery.Value, _ = json.MarshalIndent(result, "", "\t")
		// show all leaf of zktree
		// case "leaf":
		// 	resQuery.Value, _ = json.MarshalIndent(app.leafNode,"", "\t")
		default:
	}
	resQuery.Height = app.height
	return resQuery
}

func (DApplication) InitChain(req abcitypes.RequestInitChain) abcitypes.ResponseInitChain {
	return abcitypes.ResponseInitChain{}
}

func (DApplication) BeginBlock(req abcitypes.RequestBeginBlock) abcitypes.ResponseBeginBlock {
	return abcitypes.ResponseBeginBlock{}
}

func (DApplication) EndBlock(req abcitypes.RequestEndBlock) abcitypes.ResponseEndBlock {
	return abcitypes.ResponseEndBlock{}
}

func (DApplication) ListSnapshots(abcitypes.RequestListSnapshots) abcitypes.ResponseListSnapshots {
	return abcitypes.ResponseListSnapshots{}
}

func (DApplication) OfferSnapshot(abcitypes.RequestOfferSnapshot) abcitypes.ResponseOfferSnapshot {
	return abcitypes.ResponseOfferSnapshot{}
}

func (DApplication) LoadSnapshotChunk(abcitypes.RequestLoadSnapshotChunk) abcitypes.ResponseLoadSnapshotChunk {
	return abcitypes.ResponseLoadSnapshotChunk{}
}

func (DApplication) ApplySnapshotChunk(abcitypes.RequestApplySnapshotChunk) abcitypes.ResponseApplySnapshotChunk {
	return abcitypes.ResponseApplySnapshotChunk{}
}

