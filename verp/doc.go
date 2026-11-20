// Package verp writes and reads Variable Envelope Return Path addresses: the
// bounce address of one message, "bounces+<id>.<tag>@<domain>", whose local
// part says which message a bounce answers.
//
// The tag is a truncated HMAC-SHA-256 over the message id and the domain, so
// nobody who does not hold the key can make an address that decodes: a bounce
// aimed at the wrong message, or a forged one, is refused before anything is
// looked up. The address is lowercase throughout because mail systems are
// free to change the case of a local part.
//
// The package depends on the standard library only.
package verp
