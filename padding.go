package streamcrypt

import (
	"bytes"
)

//原文必须填充至blocksize的整数倍，填充方法可以参见https://tools.ietf.org/html/rfc5246#section-6.2.3.2
func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize //需要padding的数目
	//只要少于256就能放到一个byte中，默认的blockSize=16(即采用16*8=128, AES-128长的密钥)
	//最少填充1个byte，如果原文刚好是blocksize的整数倍，则再填充一个blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding) //生成填充的文本
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	// fmt.Println("unpadding:", string(origData), length, unpadding)
	return origData[:(length - unpadding)]
}
