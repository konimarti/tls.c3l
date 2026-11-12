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
		if (total > 65535) return BAD_ALPN~;
	}
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

// ---------------------------------------------------------------------------------------------
// ClientHello (RFC 8446 4.1.2, extensions 4.2). Used to inspect what the engine sends.

const ushort EXT_SERVER_NAME = 0;
const ushort EXT_SUPPORTED_GROUPS = 10;
const ushort EXT_ALPN = 16;
const ushort EXT_SUPPORTED_VERSIONS = 43;

struct ClientHelloInfo
{
	ushort legacy_version;
	String server_name;          // empty when there is no SNI
	String[] alpn;
	ushort[] supported_versions; // empty when the extension is absent
	ushort[] supported_groups;   // empty when the extension is absent
	ushort[] cipher_suites;
	Allocator allocator;
}

fn void ClientHelloInfo.free(&self)
{
	alloc::free(self.allocator, self.server_name.ptr);
	foreach (a : self.alpn) alloc::free(self.allocator, a.ptr);
	alloc::free(self.allocator, self.alpn.ptr);
	alloc::free(self.allocator, self.supported_versions.ptr);
	alloc::free(self.allocator, self.supported_groups.ptr);
	alloc::free(self.allocator, self.cipher_suites.ptr);
	*self = {};
}

// Bounds-checked big-endian reader: every overrun is BAD_HANDSHAKE.
struct Reader
{
	char[] data;
	usz pos;
}

fn usz Reader.remaining(&self) => self.data.len - self.pos;

fn char? Reader.u8(&self)
{
	if (self.remaining() < 1) return BAD_HANDSHAKE~;
	return self.data[self.pos++];
}

fn ushort? Reader.u16(&self)
{
	if (self.remaining() < 2) return BAD_HANDSHAKE~;
	ushort v = (ushort)self.data[self.pos] << 8 | self.data[self.pos + 1];
	self.pos += 2;
	return v;
}

fn char[]? Reader.take(&self, usz n)
{
	if (self.remaining() < n) return BAD_HANDSHAKE~;
	char[] s = self.data[self.pos:n];
	self.pos += n;
	return s;
}

fn String? dup_bytes(Allocator allocator, char[] src)
{
	if (src.len == 0) return (String){};
	char[] copy = alloc::alloc_array_try(allocator, char, (sz)src.len)!;
	copy[..] = src[..];
	return (String)copy;
}

// A list of big-endian u16 values inside `r` that must fill `n` bytes exactly (n even).
fn ushort[]? read_u16_list(Allocator allocator, Reader* r, usz n)
{
	if (n % 2 != 0) return BAD_HANDSHAKE~;
	char[] raw = r.take(n)!;
	usz count = n / 2;
	if (count == 0) return (ushort[]){};
	ushort[] out = alloc::alloc_array_try(allocator, ushort, (sz)count)!;
	for (usz i = 0; i < count; i++) out[i] = (ushort)raw[2 * i] << 8 | raw[2 * i + 1];
	return out;
}

// Input: one TLS record (header included) carrying a whole ClientHello. Bytes after the record are ignored.
// SHORT_INPUT: the record is not complete. BAD_RECORD: bad record header. BAD_HANDSHAKE: not a handshake record,
// not a ClientHello, a length that overruns or disagrees, or malformed fields.
fn ClientHelloInfo? parse_client_hello(char[] record, Allocator allocator)
{
	RecordHeader rh = parse_record_header(record)!;
	if (record.len < RECORD_HEADER_LEN + rh.length) return SHORT_INPUT~;
	if (rh.type != ContentType.HANDSHAKE.wire) return BAD_HANDSHAKE~;
	Reader rec = { .data = record[RECORD_HEADER_LEN:rh.length] };

	if (rec.u8()! != 1) return BAD_HANDSHAKE~; // handshake type client_hello
	usz hs_hi = rec.u8()!;
	usz hs_mid = rec.u8()!;
	usz hs_lo = rec.u8()!;
	usz hs_len = hs_hi << 16 | hs_mid << 8 | hs_lo;
	if (hs_len != rec.remaining()) return BAD_HANDSHAKE~;
	Reader r = { .data = rec.take(hs_len)! };

	ClientHelloInfo info = { .allocator = allocator };
	defer catch info.free();

	info.legacy_version = r.u16()!;
	r.take(32)!;                                // random
	usz session_id_len = r.u8()!;               // legacy_session_id<0..32>
	if (session_id_len > 32) return BAD_HANDSHAKE~;
	r.take(session_id_len)!;
	info.cipher_suites = read_u16_list(allocator, &r, r.u16()!)!;
	if (info.cipher_suites.len == 0) return BAD_HANDSHAKE~; // cipher_suites<2..2^16-2>
	usz compression_len = r.u8()!;              // legacy_compression_methods<1..2^8-1>
	if (compression_len == 0) return BAD_HANDSHAKE~;
	r.take(compression_len)!;
	if (r.remaining() == 0) return info;        // no extensions (allowed by the grammar)
	bool seen_sni, seen_groups, seen_versions, seen_alpn;
	char[8192] seen_types;                      // one bit per extension type
	seen_types[..] = 0;

	usz ext_total = r.u16()!;
	if (ext_total != r.remaining()) return BAD_HANDSHAKE~;
	while (r.remaining() > 0)
	{
		ushort ext_type = r.u16()!;
		Reader ext = { .data = r.take(r.u16()!)! };
		// RFC 8446 4.2: no extension type may appear twice
		if (seen_types[ext_type / 8] & (char)(1 << (ext_type % 8))) return BAD_HANDSHAKE~;
		seen_types[ext_type / 8] |= (char)(1 << (ext_type % 8));
		switch (ext_type)
		{
			case EXT_SERVER_NAME:
				if (seen_sni || ext.remaining() == 0) return BAD_HANDSHAKE~;
				seen_sni = true;
				Reader list = { .data = ext.take(ext.u16()!)! };
				if (ext.remaining() != 0) return BAD_HANDSHAKE~;
				bool seen_host_name = false;
				while (list.remaining() > 0)
				{
					char name_type = list.u8()!;
					char[] name = list.take(list.u16()!)!;
					if (name_type == 0)
					{
						// at most one name of each type in the list
						if (info.server_name.len > 0 || seen_host_name) return BAD_HANDSHAKE~;
						seen_host_name = true;
						info.server_name = dup_bytes(allocator, name)!;
					}
				}
			case EXT_SUPPORTED_GROUPS:
				if (seen_groups) return BAD_HANDSHAKE~;
				seen_groups = true;
				info.supported_groups = read_u16_list(allocator, &ext, ext.u16()!)!;
				if (ext.remaining() != 0) return BAD_HANDSHAKE~;
			case EXT_SUPPORTED_VERSIONS:
				if (seen_versions) return BAD_HANDSHAKE~;
				seen_versions = true;
				info.supported_versions = read_u16_list(allocator, &ext, ext.u8()!)!;
				if (ext.remaining() != 0) return BAD_HANDSHAKE~;
			case EXT_ALPN:
				if (seen_alpn) return BAD_HANDSHAKE~;
				seen_alpn = true;
				Reader list = { .data = ext.take(ext.u16()!)! };
				if (ext.remaining() != 0) return BAD_HANDSHAKE~;
				usz count = 0;
				Reader probe = list;
				while (probe.remaining() > 0)
				{
					if (probe.take(probe.u8()!)!.len == 0) return BAD_HANDSHAKE~;
					count++;
				}
				if (count == 0) return BAD_HANDSHAKE~;
				String[] names = alloc::alloc_array_try(allocator, String, (sz)count)!;
				foreach (&n : names) *n = (String){};
				info.alpn = names;
				foreach (&n : names) *n = dup_bytes(allocator, list.take(list.u8()!)!)!;
			default:
				break;
		}
	}
	return info;
}
