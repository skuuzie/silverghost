# silverghost

a very simple file encryptor-decryptor, merely a fun project for cryptography practice in golang

---

### Why?

you want to effortlessly protect a super secret file with (unnecessarily) complex security? this program is for you, just drag and drop and done.

silverghost is just a cool name that i thought about back then

### How-To

- Drag and drop the file you want to encrypt to the executable and the encrypted file will be outputted in the same folder with random 16-char filename (.e.g `0123456789abcdef`)
- To decrypt the file, do the same (drag and drop)

don't worry about losing the original filename, the decrypted file output will automatically have it.

### Consideration

- The secret key is hardcoded in `crypto.go` named `hardKey`, password-based implementation is 100% possible as you can change it to any value you want

- The file is fully read to memory, meaning your RAM can only take you so far - however you can always implement a progressive filestream reading!