package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"github.com/keybase/go-crypto/brainpool"
)

func v1_verify(dg15, sod string) bool {
	var verify_result = true
	dg15_bytes, err := hex.DecodeString(dg15)
	if err != nil {
		fmt.Println(err)
		return false
	}
	dg15_digest := sha256.Sum256(dg15_bytes)
	sod_pkcs7_raw, err := hex.DecodeString(sod[8:])
	if err != nil {
		fmt.Println(err)
		return false
	}
	var sod_pkcs7 []asn1.RawValue
	_, err = asn1.Unmarshal(sod_pkcs7_raw, &sod_pkcs7)
	if err != nil {
		fmt.Println(err)
		return false
	}
	dg_hash_raw := sod_pkcs7[1].Bytes
	var dg_hash []asn1.RawValue
	_, err = asn1.Unmarshal(dg_hash_raw, &dg_hash)
	if err != nil {
		fmt.Println(err)
		return false
	}
	listDgs_hash_raw := dg_hash[2].Bytes[37:]
	var listDgs_hash []asn1.RawValue
	_, err = asn1.Unmarshal(listDgs_hash_raw, &listDgs_hash)
	if err != nil {
		fmt.Println(err)
		return false
	}
	dg15_hash_raw := listDgs_hash[5].Bytes[3:]
	var dg15_hash []byte
	_, err = asn1.Unmarshal(dg15_hash_raw, &dg15_hash)
	if err != nil {
		fmt.Println(err)
		return false
	}
	verify_result = verify_result && bytes.Equal(dg15_hash, dg15_digest[:])

	signature_raw := dg_hash[4].Bytes
	var list_contain_r_s []asn1.RawValue
	_, err = asn1.Unmarshal(signature_raw, &list_contain_r_s)
	if err != nil {
		fmt.Println(err)
		return false
	}
	r_s_raw := list_contain_r_s[5].Bytes
	var r_s []*big.Int
	_, err = asn1.Unmarshal(r_s_raw, &r_s)
	if err != nil {
		fmt.Println(err)
		return false
	}
	var r = r_s[0]
	var s = r_s[1]

	cert_sig_raw := dg_hash[3].Bytes
	var cert_sig []asn1.RawValue
	_, err = asn1.Unmarshal(cert_sig_raw, &cert_sig)
	if err != nil {
		fmt.Println(err)
		return false
	}
	list_contains_pub_raw := cert_sig[0].FullBytes
	var list_contains_pub []asn1.RawValue
	_, err = asn1.Unmarshal(list_contains_pub_raw, &list_contains_pub)
	if err != nil {
		fmt.Println(err)
		return false
	}
	list_contains_pub_x_and_y_raw := list_contains_pub[6].FullBytes
	var list_contains_pub_x_and_y []asn1.RawValue
	_, err = asn1.Unmarshal(list_contains_pub_x_and_y_raw, &list_contains_pub_x_and_y)
	if err != nil {
		fmt.Println(err)
		return false
	}
	pub_x_and_y_hex := hex.EncodeToString(list_contains_pub_x_and_y[1].Bytes[2:])

	pub_x := new(big.Int)
	pub_y := new(big.Int)
	pub_x.SetString(pub_x_and_y_hex[0:len(pub_x_and_y_hex)/2],16)
	pub_y.SetString(pub_x_and_y_hex[len(pub_x_and_y_hex)/2:], 16)

	cert_sig_r_and_s_raw := cert_sig[2].Bytes[1:]
	var cert_sig_r_and_s []*big.Int
	_, err = asn1.Unmarshal(cert_sig_r_and_s_raw, &cert_sig_r_and_s)
	if err != nil {
		fmt.Println(err)
		return false
	}
	var cert_r = cert_sig_r_and_s[0]
	var cert_s = cert_sig_r_and_s[1]

	tbs_cert_data := list_contains_pub_raw
	var cert_digest = sha512.Sum384(tbs_cert_data)

	var sign_message_body_raw = list_contain_r_s[3].Bytes 
	var sign_message = []byte{0x31, byte(len(sign_message_body_raw))}
	sign_message = append(sign_message, sign_message_body_raw...)
	sign_digest := sha256.Sum256(sign_message)

	curvebrainpoolP384r1 := brainpool.P384r1()
	var cert_pubkey = ecdsa.PublicKey{
		Curve: curvebrainpoolP384r1,
		X: pub_x,
		Y: pub_y,
	}
	var verified_signeddata = ecdsa.Verify(&cert_pubkey, sign_digest[:], r, s)
	verify_result = verify_result && verified_signeddata

	ca_pub_x := new(big.Int)
	ca_pub_y := new(big.Int)
	ca_pub_x.SetString("5705586746797687392276527904990313555022905475611271258729414636068323857880334000957361424951661974682935706611888", 10)
	ca_pub_y.SetString("7821704373206592378644977211567592118672246135776362491204878202396889655625917188376232816427307041739256606332695", 10)
	var ca_pubkey = ecdsa.PublicKey{
		Curve: elliptic.P384(),
		X: ca_pub_x,
		Y: ca_pub_y,
	}
	var verified_cert = ecdsa.Verify(&ca_pubkey, cert_digest[:], cert_r, cert_s)
	verify_result = verify_result && verified_cert
	return verify_result
}

func v2_verify(h, aaSig, dg15 string) bool {
	m2_hex := h[:16]
	m2_int := new(big.Int)
	m2_int.SetString(m2_hex, 16)
	m2 := m2_int.Bytes()
	sig := new(big.Int)
	sig.SetString(aaSig, 16)
	der, err := hex.DecodeString(dg15[8:])
	if err != nil {
		fmt.Println(err)
		return false
	}
	var b []asn1.RawValue
	_, err = asn1.Unmarshal(der, &b)
	if err != nil {
		fmt.Println(err)
		return false
	}
	var pubkey = b[1].FullBytes[5:]
	var c []asn1.RawValue
	_, err = asn1.Unmarshal(pubkey, &c)
	if err != nil {
		fmt.Println(err)
		return false
	}
	var N_hex = hex.EncodeToString(c[0].Bytes)
	var e_hex = hex.EncodeToString(c[1].Bytes)
	n := new(big.Int)
	e := new(big.Int)
	n.SetString(N_hex, 16)
	e.SetString(e_hex, 16)
	msg_decrypted := new(big.Int)
	msg_decrypted.Exp(sig, e, n)
	message_raw := msg_decrypted.Bytes()
	t := 1
	hashlen := 160
	k := 2048
	m1_len := ((k - hashlen - 8*t - 4) - 4)
	pad := (2 + 1 + 1 + k - hashlen - m1_len - 8 * t - 4)
	m1_len_bytes := m1_len / 8
	pad_bytes := pad / 8
	hash_len_bytes := hashlen / 8
	message_end := pad_bytes + m1_len_bytes
	hash_end := message_end + hash_len_bytes
	m1 := message_raw[pad_bytes: message_end]
	hash := message_raw[message_end: hash_end]
	SHA1 := sha1.New()
	SHA1.Write(m1)
	SHA1.Write(m2)
	hash_calc := SHA1.Sum(nil)
	return bytes.Equal(hash, hash_calc)
}

func readJSONFile(filename string) ([]byte, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return data, nil
}
type Verify struct{
	H		string	`json:"h"`
	AaSig 	string	`json:"aaSig"`
	Dg15	string	`json:"dg15"`
	Sod 	string	`json:"sod"`
}
func ParseVerify(data []byte) (*Verify, error){
	var vr Verify
	err:= json.Unmarshal(data,&vr)
	if err != nil {
		return nil, err
	}
	return &vr, nil
}
// func main()  {
// 	jsonFile, err := os.Open("data.json")
// 	// if we os.Open returns an error then handle it
// 	if err != nil {
// 		fmt.Println(err)
// 	}
// 	defer jsonFile.Close()
// 	byteValue, _ := ioutil.ReadAll(jsonFile)
// 	var register_data map[string]string
//     json.Unmarshal([]byte(byteValue), &register_data)

// 	h := register_data["h"]
// 	aaSig := register_data["aaSig"]
// 	dg15 := register_data["dg15"]
// 	sod := register_data["sod"]


// 	fmt.Println(v1_verify(dg15, sod))
// 	fmt.Println(v2_verify(h, aaSig, dg15))
// }