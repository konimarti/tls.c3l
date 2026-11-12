// Pure C3, no OpenSSL. TLS record, alert and ALPN wire formats.
module tls::wire;

faultdef SHORT_INPUT, BAD_RECORD, BAD_HANDSHAKE, BAD_ALPN;

// 5 + 2^14 + 2048: the largest record (header included) any TLS version allows (RFC 5246 6.2.3).
const usz RECORD_MAX_WIRE = 5 + 16384 + 2048;
const usz RECORD_HEADER_LEN = 5;
const usz MAX_RECORD_BODY = 16384 + 2048;

enum ContentType : char (char wire)
{
	CHANGE_CIPHER_SPEC { 20 },
	ALERT { 21 },
	HANDSHAKE { 22 },
	APPLICATION_DATA { 23 },
}

struct RecordHeader
{
	char type;               // raw byte, may be unknown: see is_known_content_type
	ushort legacy_version;   // raw, not validated here
	ushort length;
}

// RFC 8446 5.1 / RFC 5246 6.2.1: type u8, version u16 (big endian), length u16 (big endian).
// SHORT_INPUT when fewer than 5 bytes, BAD_RECORD when length > 2^14 + 2048.
// Unknown types and versions are returned as they are; the caller decides what to do with them.
fn RecordHeader? parse_record_header(char[] data)
{
	if (data.len < RECORD_HEADER_LEN) return SHORT_INPUT~;
	RecordHeader h = {
		.type = data[0],
		.legacy_version = (ushort)data[1] << 8 | data[2],
		.length = (ushort)data[3] << 8 | data[4],
	};
	if (h.length > MAX_RECORD_BODY) return BAD_RECORD~;
	return h;
}

fn bool is_known_content_type(char type)
{
	return type >= ContentType.CHANGE_CIPHER_SPEC.wire && type <= ContentType.APPLICATION_DATA.wire;
}

struct Alert
{
	char level;        // 1 warning, 2 fatal
	char description;
}

// RFC 8446 6: exactly two bytes. SHORT_INPUT if fewer, BAD_RECORD if more.
fn Alert? parse_alert(char[] body)
{
	if (body.len < 2) return SHORT_INPUT~;
	if (body.len > 2) return BAD_RECORD~;
	return { .level = body[0], .description = body[1] };
}

// Names from RFC 8446 6.2 and the IANA TLS Alert registry.
fn String alert_name(char description)
{
	switch (description)
	{
		case 0: return "close_notify";
		case 10: return "unexpected_message";
		case 20: return "bad_record_mac";
		case 22: return "record_overflow";
		case 40: return "handshake_failure";
		case 42: return "bad_certificate";
		case 43: return "unsupported_certificate";
		case 44: return "certificate_revoked";
		case 45: return "certificate_expired";
		case 46: return "certificate_unknown";
		case 47: return "illegal_parameter";
		case 48: return "unknown_ca";
		case 49: return "access_denied";
		case 50: return "decode_error";
		case 51: return "decrypt_error";
		case 70: return "protocol_version";
		case 71: return "insufficient_security";
		case 80: return "internal_error";
		case 86: return "inappropriate_fallback";
		case 90: return "user_canceled";
		case 109: return "missing_extension";
		case 110: return "unsupported_extension";
		case 112: return "unrecognized_name";
		case 113: return "bad_certificate_status_response";
		case 115: return "unknown_psk_identity";
		case 116: return "certificate_required";
		case 120: return "no_application_protocol";
		default: return "unknown_alert";
	}
}

// RFC 7301 3.1: concatenated names, each with a 1-byte length prefix, as SSL_CTX_set_alpn_protos wants it.
// Each name must be 1..255 bytes and the total at most 65535, else BAD_ALPN.
// An empty list returns an empty slice (no ALPN: the caller skips the call).
fn char[]? encode_alpn(String[] protos, Allocator allocator)
{
	usz total = 0;
	foreach (p : protos)
	{
		if (p.len == 0 || p.len > 255) return BAD_ALPN~;
		total += 1 + p.len;
	}
	if (total > 65535) return BAD_ALPN~;
	if (total == 0) return (char[]){};
	char[] out = alloc::alloc_array_try(allocator, char, (sz)total)!;
	usz at = 0;
	foreach (p : protos)
	{
		out[at++] = (char)p.len;
		out[at:p.len][..] = ((char[])p)[..];
		at += p.len;
	}
	return out;
}
