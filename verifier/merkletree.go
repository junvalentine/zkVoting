package verifier

import (
	"errors"
	"math/big"
)
type ZkTree struct {
	levels           int
	nextIndex        int
	currentRootIndex int
	filledsubTree    map[int]*big.Int
	roots            map[int]*big.Int
	layer            map[int][]*big.Int
	zeroes 			 map[int]*big.Int
	hasher			 *MimcSponge
}



func (t *ZkTree) QuickInsert(leaf *big.Int) (int, error) {
	nextIndex := t.nextIndex
	if nextIndex >= 1<<t.levels {
		return -1, errors.New("Merkle tree is full. No more leaves can be added")
	}
	t.layer[0] = append(t.layer[0],leaf)
	currentIndex := nextIndex
	currentLevelHash := leaf
	var left, right *big.Int

	for i := 0; i < t.levels; i++ {
		if currentIndex%2 == 0 {
			left = currentLevelHash
			right = t.zeroes[i]
			t.filledsubTree[i] = currentLevelHash
		} else {
			left = t.filledsubTree[i]
			right = currentLevelHash
		}
		temp_out,_ := t.hasher.MultiHash([]*big.Int{left, right},nil,1)
		currentLevelHash = temp_out[0]
		currentIndex /= 2
	}

	newRootIndex := (t.currentRootIndex + 1) 
	t.currentRootIndex = newRootIndex
	t.roots[newRootIndex] = currentLevelHash
	t.nextIndex = nextIndex + 1
	return nextIndex, nil
}

// func (t *zkTree) isKnownRoot(root big.Int) (bool){
// 	if root == *nil {
// 		return false
// 	}
// 	if root == t.getRoot() {
// 		return true
// 	} else {
// 		return false
// 	}

// }

func (t *ZkTree) GetRoot() (*big.Int){
	return t.roots[t.currentRootIndex]
}


func (t *ZkTree) generateZeroes()  {
	zero := new(big.Int)
	zero.SetString("21663839004416932945382355908790599225266501822907911457504978515578255421292",10) // keccak256("tornado") % Field
	t.zeroes[0] = zero
	t.filledsubTree[0] = zero
	for i := 1; i <= t.levels; i++{
		
		temp_out,_ := t.hasher.MultiHash([]*big.Int{t.zeroes[i-1],t.zeroes[i-1]},nil,1)
		t.zeroes[i] = temp_out[0]
		t.filledsubTree[i] = temp_out[0]
	}
	
}

func (t *ZkTree) indexOf(element *big.Int) int {
	for i := 0; i < len(t.layer[0]); i++ {
		if t.layer[0][i].Cmp(element) == 0 {
			return i
		}
	}
	return -1
}

func (t *ZkTree) insert(element *big.Int) error {
	if len(t.layer[0]) >= 1<<t.levels {
		return errors.New("tree is full")
	}
	t.update(len(t.layer[0]), element)
	
	return nil
}


func (t *ZkTree) update(index int, element *big.Int) error {
	if index < 0 || index > len(t.layer[0]) || index >= 1<<t.levels {
		return errors.New("insert index out of bounds: " + string(index))
	}
	t.layer[0] = append(t.layer[0],element)
	
	t.processUpdate(index)
	return nil
}

func (t *ZkTree) path(index int) (map[int]*big.Int, map[int]int, error) {
	if index < 0 || index >= len(t.layer[0]) {
		return nil, nil, errors.New("index out of bounds: " + string(index))
	}
	elIndex := index
	pathElements := make(map[int]*big.Int)
	pathIndices := make(map[int]int)
	for level := 0; level < t.levels; level++ {
		pathIndices[level] = elIndex % 2
		leafIndex := elIndex ^ 1
		if leafIndex < len(t.layer[level]) {
			pathElements[level] = t.layer[level][leafIndex]
		} else {
			pathElements[level] = t.zeroes[level] // replace with zero element
		}
		elIndex >>= 1
	}
	return pathElements, pathIndices, nil
}

func (t *ZkTree) processNodes(nodes []*big.Int, layerIndex int) []*big.Int {
	length := len(nodes)
	
	currentLength := (length + 1) / 2
	currentLayer := make([]*big.Int, currentLength)
	currentLength--
	startFrom := length - ((length % 2) ^ 1)
	j := 0
	for i := startFrom; i >= 0; i -= 2 {
		if i-1 < 0 {
			break
		}
		left := nodes[i-1]
		var right *big.Int
		if i == startFrom && length%2 == 1 {
			right = t.zeroes[layerIndex-1] // replace with zero element of the level
		} else {
			right = nodes[i]
		}
		temp_out,_ := t.hasher.MultiHash([]*big.Int{left, right},nil,1)
		currentLayer[currentLength-j] = temp_out[0]
		j++
	}
	return currentLayer
}

func (t *ZkTree) processUpdate(index int) {
	for level := 1; level <= t.levels; level++ {
		index >>= 1
		left := t.layer[level-1][index*2]
		rightIndex := index*2 + 1
		var right *big.Int
		if rightIndex < len(t.layer[level-1]) {
			right = t.layer[level-1][rightIndex]

		} else {
			right = t.zeroes[level-1] 
		}
		
		temp_out,_ := t.hasher.MultiHash([]*big.Int{left, right},nil,1)
		t.layer[level][index] = temp_out[0]
	}
}
func (t *ZkTree) buildHashes() {
	for layerIndex := 1; layerIndex <= t.levels; layerIndex++ {
		nodes := t.layer[layerIndex-1]
		t.layer[layerIndex] = t.processNodes(nodes, layerIndex)
	}
}

func NewZkTree(levels int, elements []*big.Int) (*ZkTree, error) {
	if len(elements) > (1 << levels) {
		return nil, errors.New("tree is full")
	}
	t := &ZkTree{
		levels:        levels,
		filledsubTree: make(map[int]*big.Int),
		roots:         make(map[int]*big.Int),
		layer:         make(map[int][]*big.Int),
		zeroes: make(map[int]*big.Int),
		nextIndex: 0,
		currentRootIndex: 0,
		hasher: NewMimcSponge(),
	}
	
	t.layer[0] = elements
	
	t.generateZeroes()

	t.buildHashes()

	return t, nil
}

func (t *ZkTree) checkMerkleProof(pathElements map[int]*big.Int, pathIndices map[int]int, element *big.Int) (*big.Int, error) {
	hashes := make([]*big.Int, t.levels)
	for i := 0; i < t.levels; i++ {
		var in0, in1 *big.Int
		if i == 0 {
			in0 = element
		} else {
			in0 = hashes[i-1]
		}
		in1 = pathElements[i]

		if pathIndices[i] == 0 {
			temp_out, err := t.hasher.MultiHash([]*big.Int{in0, in1}, nil, 1)
			if err != nil {
				return nil, err
			}
			hashes[i] = temp_out[0]
		} else {
			temp_out, err := t.hasher.MultiHash([]*big.Int{in1, in0}, nil, 1)
			if err != nil {
				return nil, err
			}
			hashes[i] = temp_out[0]
		}
	}
	return hashes[t.levels-1], nil
}
