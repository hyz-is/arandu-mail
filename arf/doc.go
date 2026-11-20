// Package arf reads Abuse Reporting Format feedback reports (RFC 5965), the
// complaints that mailbox providers send back through feedback loops when a
// reader marks a message as spam.
//
// A report is a multipart/report with a human-readable part, a
// message/feedback-report part and, usually, the original message or its
// headers. Parse reads them, tolerating the variations of the providers that
// leave out parts or fields, and exposes the header fields of the returned
// original so the sender can find which message was reported: the Message-ID
// and a custom header such as X-Meeng-Email-ID.
//
// The package depends on the standard library and on arandu-mail/mime.
package arf
