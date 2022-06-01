package basic_auth

import (
	"encoding/base64"
	"reflect"
	"unsafe"
)

func base64EncodeRealm(realm string) string {
	return base64.StdEncoding.EncodeToString(unsafeBytes(realm))
}

func base64DecodeRealm(base64realm string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(base64realm)
}

// unsafeBytes returns a byte pointer without allocation
func unsafeBytes(s string) (bs []byte) {
	sh := (*reflect.StringHeader)(unsafe.Pointer(&s))
	bh := (*reflect.SliceHeader)(unsafe.Pointer(&bs))
	bh.Data = sh.Data
	bh.Len = sh.Len
	bh.Cap = sh.Len
	return
}

// unsafeString returns a string pointer without allocation
func unsafeString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
