package silverghost_modules

// The legendary golang error checking
func check(err error) int {
	if err != nil {
		panic(err)
	}
	return 1
}
