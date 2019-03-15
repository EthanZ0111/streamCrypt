package streamcrypt

import (
	"bytes"
	"crypto/aes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"
)

func getRandomByte() ([]byte, int) {
	fp, err := os.OpenFile("/dev/random", os.O_RDONLY, 0666)
	if err != nil {
		fmt.Println(err)
		return nil, 0
	}

	n := rand.Intn(1024 * 1024)
	for n == 0 {
		n = rand.Intn(1024 * 1024)
	}
	ret := make([]byte, n)
	n, err = fp.Read(ret)
	if err != nil {
		fmt.Println(err)
		return nil, 0
	}
	ret = []byte("caasdfasdfasdfasdfasdfasdfasdfasdffasdfasdfaseasdfasdfasdfasdfafdaaaf")
	return ret, n
}

func Benchmark_Decrypt(b *testing.B) {
	oriByte, n := getRandomByte()
	if n == 0 {
		return
	}
	oriByteReader := bytes.NewBuffer(oriByte)
	encryptedByteBuf := bytes.NewBuffer(nil)
	aesCrypt, err := NewAESPKCS5CBCStreamEncrypt(encryptedByteBuf, aesIv, aesKey)
	if err != nil {
		b.Error(err)
		return
	}
	_, err = io.Copy(aesCrypt, oriByteReader)
	if err != nil {
		b.Error(err)
		return
	}
	encryptedByte := encryptedByteBuf.Bytes()
	output := bytes.NewBuffer(nil)
	for i := 0; i < b.N; i++ {
		oriByteReader.Reset()
		oriByteReader.Write(encryptedByte)
		aesCrypt, err := NewAESPKCS5CBCStreamDecrypt(output, aesIv, aesKey)
		if err != nil {
			b.Error(err)
			return
		}
		_, err = randomIOCopy(aesCrypt, oriByteReader)
		if err != nil {
			b.Error(err)
			return
		}
		output.Reset()
	}
}

func Benchmark_Encrypt(b *testing.B) {
	oriByte, n := getRandomByte()
	if n == 0 {
		return
	}
	output := bytes.NewBuffer(nil)
	oriByteReader := bytes.NewBuffer(nil)
	for i := 0; i < b.N; i++ {
		oriByteReader.Reset()
		oriByteReader.Write(oriByte)
		aesCrypt, err := NewAESPKCS5CBCStreamEncrypt(output, aesIv, aesKey)
		if err != nil {
			b.Error(err)
			return
		}
		_, err = randomIOCopy(aesCrypt, oriByteReader)
		if err != nil {
			b.Error(err)
			return
		}
		output.Reset()
	}
}

func randomIOCopy(dst io.Writer, src io.Reader) (written int64, err error) {
	for {
		size := rand.Int31n(10)
		for size == 0 {
			size = rand.Int31n(10)
		}
		buf := make([]byte, size)
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = fmt.Errorf("Short writen")
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err
}

func TestStreamCrypt(t *testing.T) {
	oriByte, n := getRandomByte()
	if n == 0 {
		return
	}
	oriByteReader := bytes.NewBuffer(oriByte)
	encryptedByte := bytes.NewBuffer(nil)
	aesCrypt, err := NewAESPKCS5CBCStreamEncrypt(encryptedByte, aesIv, aesKey)
	if err != nil {
		t.Error(err)
		return
	}
	cryptBC, err := randomIOCopy(aesCrypt, oriByteReader)
	if err != nil {
		t.Error(err)
		return
	}
	aesCrypt.Flush()
	if err != nil {
		t.Error(err)
		return
	}
	fmt.Printf("crypt %d byte with output size %d\n", int(cryptBC), encryptedByte.Len())
	// fmt.Println("Encrypt:", string(encryptedByte.Bytes()))
	// b, err := DecryptoAllExamPackage(encryptedByte.Bytes())
	// fmt.Println("$$$$$$$", string(b), err)

	if len(oriByte) != int(cryptBC) {
		t.Errorf("Not full crypted %d <> %d\n", cryptBC, len(oriByte))
		return
	}
	if encryptedByte.Len()-int(cryptBC) > aes.BlockSize {
		t.Error("Error crypt with to large output bytes", encryptedByte.Len())
		return
	}
	newDecryptByte := bytes.NewBuffer(nil)
	aesDecrypt, err := NewAESPKCS5CBCStreamDecrypt(newDecryptByte, aesIv, aesKey)
	if err != nil {
		t.Error(err)
		return
	}
	decryptBC, err := randomIOCopy(aesDecrypt, encryptedByte)
	aesDecrypt.Flush()
	fmt.Printf("Decrypted %d byte with output size %d\n", int(decryptBC), newDecryptByte.Len())
	// fmt.Println("Decrypt:", string(newDecryptByte.Bytes()))
	if newDecryptByte.Len() != len(oriByte) {
		t.Errorf("Error decrypt after encrypt with len ori %d <> after %d\n", oriByteReader.Len(), newDecryptByte.Len())
		return
	}
	if !bytes.Equal(oriByte, newDecryptByte.Bytes()) {
		t.Error("Not equal between ori byte and decrypt byte", bytes.Equal(oriByte, newDecryptByte.Bytes()))
		fmt.Println("ori:after", oriByte, newDecryptByte.Bytes())
		return
	}
}
