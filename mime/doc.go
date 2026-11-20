// Package mime builds and reads Internet messages (RFC 5322) and their MIME
// structure (RFC 2045 to RFC 2049).
//
// The Builder turns the parts of an e-mail into wire-ready bytes: header
// folding, RFC 2047 encoded words for non-ASCII headers, RFC 2231 parameters,
// multipart/alternative, related and mixed, quoted-printable or base64 chosen
// from the content, CRLF line endings and the 998-octet line limit. Every value
// that reaches a header is checked, so a CR, LF or NUL in a subject, a display
// name, a custom header or a file name is an error and never a second header.
//
// Parse reads a message back into a structure: addresses, subject, text, HTML,
// attachments and the headers in order, decoding transfer encodings and the
// common charsets (UTF-8, US-ASCII, ISO-8859-1, ISO-8859-15 and Windows-1252).
// ParseEntity exposes the full MIME tree for callers, such as the DSN and ARF
// readers, that need a part of it.
//
// The package depends on the standard library only.
package mime
