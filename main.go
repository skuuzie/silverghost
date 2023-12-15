package main

import (
	"os"
	"silverghost/silverghost_modules"
)

func main() {

	init := silverghost_modules.CheckParcel(os.Args[1])

	if init == 0 {
		test := silverghost_modules.NewPack(os.Args[1])
		silverghost_modules.Pack(test, "")
	} else if init == 1 {
		silverghost_modules.Unpack(os.Args[1], "")
	}

}
