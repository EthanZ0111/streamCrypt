package streamcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

var (
	//秘钥长度需要时AES-128(16bytes)或者AES-256(32bytes)
	aesKey = []byte("example key 1234")
	aesIv  = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16}
)

type AESPKCS5CBCStreamEncrypt struct {
	byteCache    *bytes.Buffer
	outputWriter io.Writer
	aesCipher    cipher.BlockMode
	iv           []byte
	key          []byte
}

func NewAESPKCS5CBCStreamEncrypt(output io.Writer, iv, key []byte) (*AESPKCS5CBCStreamEncrypt, error) {
	block, err := aes.NewCipher(key) //生成加密用的block
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, iv)
	return &AESPKCS5CBCStreamEncrypt{
		byteCache:    new(bytes.Buffer),
		outputWriter: output,
		aesCipher:    mode,
		iv:           iv,
		key:          key,
	}, nil
}

func (c *AESPKCS5CBCStreamEncrypt) Write(p []byte) (int, error) {
	src := p
	srcLen := len(p)

	if c.byteCache.Len() != 0 {
		_, err := c.byteCache.Write(p)
		if err != nil {
			return 0, err
		}
		src = c.byteCache.Bytes()
		srcLen = c.byteCache.Len()
	} else {
		bc := srcLen / aes.BlockSize
		if bc <= 0 {
			c.byteCache.Write(p)
			return len(p), nil
		}
	}

	padding := srcLen % aes.BlockSize
	cryptLen := srcLen - padding
	encryptByte := src[:cryptLen]
	paddingByte := src[cryptLen:]
	// fmt.Printf("[DEBUG] Need crypt len %d, real crypt len %d, save to cache len %d\n", srcLen, cryptLen, padding)
	out := make([]byte, cryptLen)
	c.aesCipher.CryptBlocks(out, encryptByte)
	_, err := writeToOutput(c.outputWriter, out)
	if err != nil {
		return -1, err
	}
	c.byteCache.Reset()
	c.byteCache.Write(paddingByte)
	return len(p), nil
}

func (c *AESPKCS5CBCStreamEncrypt) Flush() (int, error) {
	var cryptByte []byte
	if c.byteCache.Len() != 0 {
		cryptByte = PKCS5Padding(c.byteCache.Bytes(), aes.BlockSize)

	} else {
		cryptByte = bytes.Repeat([]byte{byte(aes.BlockSize)}, aes.BlockSize)
	}
	output := make([]byte, aes.BlockSize)
	c.aesCipher.CryptBlocks(output, cryptByte)
	return writeToOutput(c.outputWriter, output)
}

func writeToOutput(w io.Writer, b []byte) (int, error) {
	n, err := w.Write(b)
	if err != nil {
		return 0, err
	}
	// fmt.Printf("[DEBUG] Wirte %d byte to outputer\n", n)
	return n, err
}

func CryptoAllExamPackage(ori []byte) ([]byte, error) {
	needPadding := false
	if len(ori)%aes.BlockSize != 0 {
		fmt.Println("[DEBUG] Need padding")
		ori = PKCS5Padding(ori, aes.BlockSize)
		needPadding = true
	}
	output := make([]byte, len(ori))
	block, err := aes.NewCipher(aesKey) //生成加密用的block
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCEncrypter(block, aesIv)
	mode.CryptBlocks(output, ori)
	if !needPadding {
		//如果原文刚好是blocksize的整数倍，则再填充一个blocksize
		padtext := bytes.Repeat([]byte{byte(aes.BlockSize)}, aes.BlockSize)
		output = append(output, padtext...)
	}
	return output, nil
}
