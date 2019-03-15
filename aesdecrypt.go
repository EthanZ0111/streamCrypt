package streamcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
)

type AESPKCS5CBCStreamDecrypt struct {
	byteCache    *bytes.Buffer
	outputWriter io.Writer
	aesCipher    cipher.BlockMode
	iv           []byte
	key          []byte
}

func NewAESPKCS5CBCStreamDecrypt(output io.Writer, iv, key []byte) (*AESPKCS5CBCStreamDecrypt, error) {
	block, err := aes.NewCipher(key) //生成加密用的block
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	return &AESPKCS5CBCStreamDecrypt{
		byteCache:    new(bytes.Buffer),
		outputWriter: output,
		aesCipher:    mode,
		iv:           iv,
		key:          key,
	}, nil
}

func (c *AESPKCS5CBCStreamDecrypt) Write(p []byte) (int, error) {
	// oriByte := p
	srcLen := len(p)
	_, err := c.byteCache.Write(p)
	if err != nil {
		return 0, err
	}
	oriLen := c.byteCache.Len()
	bc := oriLen / aes.BlockSize
	if bc <= 1 {
		// c.byteCache.Write(p)
		return srcLen, nil
	}
	oriByte := c.byteCache.Bytes()
	padCount := oriLen % aes.BlockSize
	if padCount == 0 {
		bc = bc - 1
	}
	decryptLen := bc * aes.BlockSize
	src := oriByte[:decryptLen]
	padByte := oriByte[decryptLen:]
	// out := make([]byte, bc*aes.BlockSize)
	// defer func() {
	// 	fmt.Println("&&&&&", string(padByte), bc)
	// 	fmt.Printf("[DEBUG] Need decrypt len %d, real crypt len %d, save to cache len %d\n", srcLen, bc*aes.BlockSize, len(padByte))
	// 	fmt.Println("$$$$$$", string(p), string(src), string(padByte), string(out), bc*aes.BlockSize)
	// }()
	c.aesCipher.CryptBlocks(src, src)
	_, err = writeToOutput(c.outputWriter, src)
	if err != nil {
		return -1, err
	}
	c.byteCache.Reset()
	c.byteCache.Write(padByte)
	return srcLen, nil
}

func (c *AESPKCS5CBCStreamDecrypt) Flush() (int, error) {
	if c.byteCache.Len() != aes.BlockSize {
		return -1, fmt.Errorf("Error flush aes decrypt left byte size %d <> aes block size %d", c.byteCache.Len(), aes.BlockSize)
	}
	ori := c.byteCache.Bytes()
	// fmt.Println("##### ori", string(ori))
	// ret := make([]byte, len(ori))
	c.aesCipher.CryptBlocks(ori, ori)
	// fmt.Println("##### after", string(ori))
	ret := PKCS5UnPadding(ori)
	return writeToOutput(c.outputWriter, ret)
}

func DecryptoAllExamPackage(ori []byte) ([]byte, error) {
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	mode := cipher.NewCBCDecrypter(block, aesIv)
	// CryptBlocks可以原地更新
	mode.CryptBlocks(ori, ori)
	ret := PKCS5UnPadding(ori)
	return ret, nil
}
