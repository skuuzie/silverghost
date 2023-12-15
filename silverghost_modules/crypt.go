package silverghost_modules

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

type KeySet struct {
	FileKey []byte
	FileIv  []byte
}

// Hardcoded "secret"
var HardEntropy = []byte{12, 73, 78, 46, 22, 65, 110, 101, 38, 3, 83, 76, 12, 89, 24, 117, 114, 7, 117, 68, 63, 8, 10, 84, 102, 18, 124, 60, 123, 100, 103, 12, 8, 27, 17, 90, 123, 12, 106, 19, 85, 40, 82, 22, 29, 33, 124, 108, 32, 14, 113, 1, 123, 121, 103, 30, 109, 76, 28, 29, 94, 69, 117, 21, 92, 123, 42, 27, 101, 98, 7, 29, 116, 22, 109, 112, 4, 87, 114, 30, 45, 15, 99, 86, 18, 27, 116, 105, 36, 41, 79, 0, 78, 73, 54, 18, 110, 91, 72, 97, 45, 104, 76, 102, 111, 108, 121, 25, 94, 78, 74, 111, 18, 36, 29, 118, 99, 89, 99, 86, 20, 32, 87, 41, 72, 114, 121, 52, 99, 80, 75, 60, 6, 109, 72, 15, 29, 83, 81, 108, 28, 48, 78, 79, 12, 14, 122, 68, 123, 2, 76, 42, 77, 75, 126, 79, 74, 64, 124, 123, 73, 61, 56, 7, 5, 35, 112, 109, 28, 35, 84, 107, 119, 27, 110, 86, 40, 85, 25, 8, 107, 27, 57, 35, 15, 56, 31, 26, 117, 16, 25, 46, 58, 10, 55, 65, 72, 93, 26, 7, 8, 14, 119, 87, 54, 30, 106, 52, 85, 46, 62, 90, 43, 75, 85, 94, 110, 8, 54, 21, 56, 107, 67, 72, 126, 94, 26, 125, 95, 116, 123, 18, 115, 27, 109, 23, 1, 87, 35, 11, 15, 117, 0, 32, 52, 119, 125, 127, 120, 38, 21, 37, 109, 71, 9, 11, 71, 44, 17, 64, 18, 27, 13, 30, 6, 50, 58, 79, 95, 29, 59, 107, 111, 21, 126, 83, 78, 11, 98, 125, 38, 31, 122, 105, 96, 40, 36, 66, 107, 116, 119, 119, 84, 30, 43, 11, 50, 88, 114, 10, 36, 6, 89, 41, 31, 12, 5, 82, 73, 105, 86, 68, 101, 40, 32, 44, 64, 8, 127, 83, 86, 122, 0, 3, 81, 95, 26, 111, 111, 94, 61, 84, 94, 19, 104, 103, 122, 85, 119, 31, 113, 110, 95, 84, 27, 12, 111, 76, 74, 26, 113, 50, 54, 17, 47, 121, 29, 117, 41, 50, 92, 78, 31, 30, 98, 114, 62, 60, 35, 65, 109, 45, 16, 120, 47, 65, 70, 31, 46, 55, 93, 10, 107, 100, 45, 20, 86, 125, 2, 114, 14, 30, 78, 62, 64, 34, 64, 58, 2, 60, 120, 84, 84, 23, 4, 36, 27, 122, 125, 10, 32, 23, 20, 67, 20, 33, 3, 24, 10, 78, 36, 26, 1, 12, 70, 100, 82, 39, 54, 62, 37, 123, 106, 55, 6, 107, 42, 69, 60, 63, 23, 107, 112, 77, 97, 115, 97, 38, 12, 116, 39, 66, 107, 55, 118, 3, 82, 108, 5, 57, 81, 53, 45, 7, 47, 104, 15, 62, 97, 112, 65, 48, 89, 103, 123, 28, 72, 127, 50, 27, 99, 46, 48, 9, 90, 63, 10, 24, 35, 101, 104, 118, 95, 28, 87, 125, 40, 73, 67, 40, 99, 116, 54, 124, 85, 115, 114, 46, 93, 101, 68, 120, 62, 113, 44, 47, 105, 118, 102, 95, 96, 76, 0, 123, 34, 96, 107, 21, 32, 9, 81, 63, 2, 23, 98, 119, 80, 60, 122, 3, 45, 10, 118, 114, 45, 34, 7, 47, 111, 4, 102, 35, 95, 92, 51, 120, 103, 89, 6, 72, 120, 96, 40, 106, 51, 62, 31, 27, 43, 93, 67, 47, 22, 46, 16, 51, 120, 65, 76, 29, 99, 12, 102, 102, 67, 5, 122, 1, 69, 125, 65, 65, 101, 58, 49, 26, 101, 116, 46, 22, 114, 76, 63, 58, 21, 118, 9, 126, 61, 79, 73, 34, 79, 99, 19, 97, 88, 73, 8, 76, 101, 32, 11, 69, 118, 127, 62, 77, 58, 81, 99, 37, 17, 72, 120, 41, 57, 108, 11, 99, 60, 83, 41, 55, 83, 1, 80, 61, 46, 120, 69, 71, 120, 5, 119, 3, 14, 39, 61, 69, 77, 3, 112, 6, 124, 118, 71, 120, 108, 45, 31, 119, 17, 97, 80, 118, 78, 124, 53, 93, 37, 62, 85, 111, 99, 46, 99, 115, 10, 47, 61, 122, 29, 24, 82, 87, 121, 70, 119, 19, 79, 8, 18, 42, 33, 71, 93, 99, 68, 24, 28, 45, 116, 103, 72, 125, 91, 12, 48, 25, 31, 112, 117, 92, 65, 99, 111, 28, 46, 91, 50, 122, 101, 2, 124, 21, 32, 32, 75, 27, 116, 80, 5, 60, 20, 64, 96, 52, 101, 103, 74, 81, 74, 84, 47, 10, 121, 115, 76, 63, 113, 70, 9, 31, 24, 57, 78, 33, 24, 48, 76, 107, 81, 27, 26, 13, 95, 62, 57, 5, 58, 124, 107, 34, 95, 63, 125, 54, 51, 107, 109, 126, 6, 82, 11, 35, 36, 23, 0, 66, 121, 40, 106, 121, 52, 126, 119, 60, 72, 40, 90, 47, 64, 98, 64, 99, 83, 94, 82, 123, 118, 2, 14, 62, 127, 34, 100, 70, 8, 86, 73, 44, 102, 124, 45, 41, 0, 69, 71, 107, 75, 104, 8, 112, 113, 22, 118, 127, 8, 102, 106, 120, 121, 10, 35, 98, 19, 64, 107, 126, 123, 112, 27, 36, 19, 127, 113, 2, 4, 114, 94, 122, 49, 97, 122, 95, 43, 45, 18, 29, 19, 29, 31, 98, 45, 28, 75, 72, 14, 34, 71, 88, 7, 2, 115, 21, 20, 106, 44, 115, 126, 26, 79, 106, 115, 94, 80, 21, 9, 117, 92, 39, 123, 83, 16, 9, 124, 37, 30, 23, 58, 45, 101, 104, 107, 21, 9, 90, 109, 49, 27, 60, 85, 76, 122, 58, 86, 50, 93, 33, 2, 50, 112, 25, 102, 8, 89, 28, 12, 107, 123, 36, 99, 32, 58, 125, 120, 34, 45, 124, 24, 25, 46, 114, 122, 107, 9}

// AES-CTR
func PerformCTR(key []byte, iv []byte, data []byte) []byte {

	ret := make([]byte, len(data))

	block, err := aes.NewCipher(key)
	check(err)

	stream := cipher.NewCTR(block, iv)

	stream.XORKeyStream(ret, data)

	return ret
}

// Higher-level function for AES-CTR
func TransformData(keyset KeySet, data []byte) []byte {

	var ret []byte

	if len(data)%2 == 0 {
		ret = PerformCTR(keyset.FileKey[32:64], keyset.FileIv[100:116], data)
	} else if len(data)%3 == 0 {
		ret = PerformCTR(keyset.FileKey[125:157], keyset.FileIv[200:216], data)
	} else {
		ret = PerformCTR(keyset.FileKey[300:332], keyset.FileIv[150:166], data)
	}

	return ret
}

// Core key & iv generation
// fyi, parcel.Header.Metadata.Entropy.CoreEntropy is randomly generated (100 bytes length) in packer.NewPack()
func GenerateKey(parcel SilverGhostParcel) KeySet {

	fkey := make([]byte, 32)
	fiv := make([]byte, 16)

	rsa := rsa.PrivateKey{}
	Initialize(&rsa)

	secentropy := RsaSign(&rsa, parcel.Header.Metadata.Entropy.CoreEntropy)

	fkey = PerformCTR(parcel.Header.Metadata.Entropy.CoreEntropy[:32], make([]byte, 16), secentropy)
	fiv = PerformCTR(parcel.Header.Metadata.Entropy.CoreEntropy[:32], make([]byte, 16), secentropy)

	for i := 0; i < int(parcel.Header.Metadata.Entropy.KeyCount); i++ {
		fkey = PerformCTR(parcel.Header.Metadata.Entropy.CoreEntropy[:32], make([]byte, 16), fkey)
		fkey = Xor(fkey, HardEntropy)
	}

	for i := 0; i < int(parcel.Header.Metadata.Entropy.IvCount); i++ {
		fiv = PerformCTR(parcel.Header.Metadata.Entropy.CoreEntropy[:32], make([]byte, 16), fiv)
		fiv = Xor(fiv, HardEntropy)
	}

	// randomize the randomized
	fkey = RsaSign(&rsa, fkey)
	fiv = RsaSign(&rsa, fiv)

	return KeySet{
		FileKey: fkey,
		FileIv:  fiv,
	}
}

// Just another obfuscation-purpose function
func Initialize(rsa *rsa.PrivateKey) {

	priv_exp, err := hex.DecodeString("c46c6d1c7e944a3921fcdad8ab415c0f9ff1c99fb331a82b61c54afb6084c84307688087ef3232a9e9e70ffd3834bffc71d5ebc39ecc07d7786a4fb8824e26df4aeddb18c175ed91312150f72bcf2b014899f3092b4ed632c94639bd28b602cccdac88b6bfbb9bd2c06e009d62c7700c087e00f0196256e70d7f72e5d34fe568b75fc6c1cd3827cdad3875ed4e2eab0b56c755a1d2cb33c615b8ea0a73ca95fc13488329a306ba4d4bbfae8c355db326245f1c748c13c6b9221664df5fcda983adff4e0a220342956344b1a056b155db5275291447f945e6a95cc67d0b431691a2f6c7b2d69afe539dbf18b6d529c927e344049bc03758a0524c51ac6e88cedd5d9da2554485d685842a16add0189aef13d0ed336d4a550e3aa0fdfc9ca54ad04c644c43dab7ff954c67ccbaeafe7ab78bf2fb2c8dc7610dbd0207da0dec8f331264f1d7361a9fc0f9125a7a20e9d5d0dce4f2d45973bdcf2f09d9bbe0f76f653ffef103922e4899b511d0cda5543e398c974323bbe9cda080386094d94fa7cc7d61e5e3e537325d958ded65793ee1abe4345ef5552d00b2be982ed20963e6304c3b0d00cae060fac357e954b96eca479820437d2ffface83b70f19691de08430ffda987ad54323a1b38cafc6fcf3923cc229f9866dcf1c70ac16aa22632ab66ddae215ccb31b96990a742e0cc7c248594e77212443e184ba0afe4eac8c7cf01")
	check(err)

	modulus, err := hex.DecodeString("d017a4dcf6dfd0e9a565b256fa5f42707e7876649cc323eeba0aa9c95f8503bf9b89beccb5a0c7481d88d7cd61bec3f9c021c214eac0b87b16c6a71d2a9c2ea2bd5eea33c7ae6c44f44c952d6a91c6f19b0610ae8716bde2c8256c1480b22859eaef006f8928cf3c86e8ebd3e241f9acb0ed35c3b5066e989ebc9f6d4cd6769ac60676e812949de80918af6b4e1ae7560aa79580c251d0bf2076ea63316819c8b3a6df53366b5e3a57566861f18ea17d7a52c8eb275b24dbe49e92bb9d3b9242645704e5b8ed637e8bff4241ee8b258520eae6bce3ec9fcd58486f68b68bf684a5334ce74de18be00958dbb730f53dec5eb2fc9d2c83f6ba9d1f9b97c00f9d8262448e1c081a3468735ed75a4952b37e9ed31924e6560628d1ca71559ba7ee2cad8626f390ad24bd407a543422376edee7cd7c103950f9a60e3eb8b2be429c6591c2420e6ce012a8b4828dafb46a3c96d840b732016b06a42454a19f15f2df7ad89330e438fb652139a07c1c4fd2da21f35e6e7bf8f1b41e3a9d6ee335719cfa4cda1aa7d348fb237b0d788a58e52f5a8eeb9937c4f4d45fd9cad635c915b8664aa23bb33b7eb21ede799adfaaeecdd6e4b13edc7d3b0094693c1c14e1041c697f39f2b85a83b1084aa169001452e0f2107c7829926a0528f5dc29a3e2439df25795bb0816795ed93eecb33dd53294cf24cc9729a5918d23ed3709695c04cc25")
	check(err)

	rsa.D = new(big.Int).SetBytes(priv_exp)
	rsa.PublicKey.N = new(big.Int).SetBytes(modulus)
	rsa.PublicKey.E = 65537
}

// Just another obfuscation-purpose function, the file isn't actually signed - key generation purpose
func RsaSign(rsak *rsa.PrivateKey, data []byte) []byte {

	hash := sha256.New()
	hash.Write(data)

	testz, err := rsa.SignPKCS1v15(nil, rsak, crypto.SHA256, hash.Sum(nil))
	check(err)

	return Xor(testz, HardEntropy)
}

// Essentially a random hexstring function
func GenerateFilename() string {
	randb := make([]byte, 8)

	_, err := rand.Read(randb)
	check(err)

	return hex.EncodeToString(randb)
}

// AES-CTR lite version
func Xor(buffer []byte, key []byte) []byte {

	ret := make([]byte, len(buffer))

	for i := 0; i < len(buffer); i++ {
		ret[i] = buffer[i] ^ key[i%len(key)]
	}

	return ret
}
