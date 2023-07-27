package verifier

import (
	"math/big"
	"fmt"
	"strings"
)

type Input struct{
	root *big.Int
    identifier *big.Int
    secret *big.Int
    pathElements map[int]*big.Int
    pathIndices map[int]int
}


func genInput(root,identifier,secret,secretHash, voting *big.Int,pathElements map[int]*big.Int, pathIndices map[int]int) (*Input,string,string){
	inp := &Input{
		root: root,
		identifier: identifier,
		secret: secret,
		pathElements: pathElements,
		pathIndices: pathIndices,
	}
	// generate string from map 
	parts := make([]string, len(pathElements))
	parts1 := make([]string, len(pathIndices))
	for i := 0; i < len(pathElements); i++ {
		parts[i] = "\""+ fmt.Sprintf("%d", pathElements[i]) + "\""
		
	}
	for i := 0; i < len(pathIndices); i++ {
		parts1[i] = fmt.Sprintf("%d", pathIndices[i])
	}
	result := fmt.Sprintf("[%s]", strings.Join(parts, ","))
	result1 := fmt.Sprintf("[%s]", strings.Join(parts1, ","))

	// make json 
	var json string
	json += fmt.Sprintln("{")
	json += fmt.Sprintf(`"root": "%s",`+"\n",root)
	json += fmt.Sprintf(`"identifier": "%s",`+"\n", identifier)
	json += fmt.Sprintf(`"secret": "%s",`+"\n", secret)
	json += fmt.Sprintf(`"pathElements": %s,`+"\n",  result)
	json += fmt.Sprintf(`"pathIndices": %s,`+"\n",  result1)
	json += fmt.Sprintf(`"voting": "%s"`+"\n",  voting)
	json += fmt.Sprintf("}")
	var json1 string
	json1 += fmt.Sprintln("[")
	json1 += fmt.Sprintf(` "%s",`+"\n",voting)
	json1 += fmt.Sprintf(` "%s"`+"\n", secretHash)
	json1 += fmt.Sprintf("]")
	return inp, json, json1
}