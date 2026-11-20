// Package dsn reads delivery status notifications (bounces) and classifies a
// failed delivery the way the Amazon SES notification does.
//
// Parse reads a standard report (RFC 3464, a multipart/report holding a
// message/delivery-status part) and, when a message is a bounce but is not
// built that way, falls back to heuristics over its text: the layouts of
// Postfix, Exim, Gmail, Microsoft and the many MTAs that write a free-form
// notice. A Report made that way says so in Heuristic, and its fields are
// best-effort.
//
// Classify and Recipient.Classification turn a reply code, an enhanced status
// code (RFC 3463) and the text of the remote server into a Type and SubType
// with the vocabulary SES uses and the useSend API exposes: Permanent,
// Transient or Undetermined, and General, NoEmail, Suppressed, MailboxFull,
// MessageTooLarge, ContentRejected or AttachmentRejected.
//
// The package depends on the standard library and on arandu-mail/mime.
package dsn
