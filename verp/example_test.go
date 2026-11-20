package verp_test

import (
	"fmt"

	"github.com/hyz-is/arandu-mail/verp"
)

func Example() {
	codec, err := verp.New("bounces", []byte("a secret of your own"))
	if err != nil {
		panic(err)
	}
	addr, _ := codec.Encode("cm3x8k2p0000108l5", "mail.acme.com")
	fmt.Println(addr)

	id, domain, err := codec.Decode("<" + addr + ">")
	fmt.Println(id, domain, err)

	_, _, err = codec.Decode("bounces+cm3x8k2p0000108l5.aaaaaaaaaaaaa@mail.acme.com")
	fmt.Println(err)

	// Output:
	// bounces+cm3x8k2p0000108l5.fijr3mu2iy3km@mail.acme.com
	// cm3x8k2p0000108l5 mail.acme.com <nil>
	// verp: the authentication tag does not match
}
