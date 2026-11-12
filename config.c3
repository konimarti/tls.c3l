// Backend independent: configuration types and input validation. No OpenSSL here.
module tls;
import tls::wire;

enum Version : int (int wire)
{
	DEFAULT { 0 },        // min -> TLS_1_2, max -> TLS_1_3
	TLS_1_2 { 0x0303 },
	TLS_1_3 { 0x0304 },
}

enum VerifyMode
{
	FULL,           // chain + hostname (zero value = default)
	CHAIN_ONLY,     // chain, no hostname check (explicit opt-out)
	PINNED_ONLY,    // no chain and no hostname check, pin_sha256 required (self-signed devices)
	INSECURE_NONE,  // accept anything; named loudly on purpose
}

// Trust rules: if ca_file or ca_dir is set, ONLY those anchors are trusted unless also_system_roots is true.
// If neither is set, the system store is used. pin_sha256 (when set) is checked after the handshake in
// every mode and must match in addition to the mode's own checks.
struct ClientConfig
{
	Version min_version;
	Version max_version;
	VerifyMode verify;            // zero value = FULL
	String ca_file;               // PEM bundle, empty = none
	String ca_dir;                // OpenSSL hashed dir, empty = none
	bool also_system_roots;       // only meaningful when ca_file/ca_dir is set
	String client_cert_file;      // PEM chain, leaf first
	String client_key_file;       // PEM, unencrypted (an encrypted key is KEY_LOAD_FAILED, never a prompt)
	char[] pin_sha256;            // empty = no pin, else exactly 32 bytes (SHA-256 of the peer certificate DER)
	String[] alpn;
	bool require_alpn;            // fault ALPN_MISMATCH when alpn is set and the server selected none
	String cipher_list;           // TLS <= 1.2, OpenSSL syntax, empty = library default
	String ciphersuites;          // TLS 1.3, empty = default
	String groups;                // e.g. "X25519:P-256"; empty = library default
	bool session_cache;           // allow export_session/import_session
	int max_chain_depth;          // 0 = DEFAULT_CHAIN_DEPTH
}

const int DEFAULT_CHAIN_DEPTH = 10;
const usz MAX_HOSTNAME_LEN = 253;      // RFC 1035 2.3.4 / RFC 6066 3
const usz MAX_LABEL_LEN = 63;          // RFC 1035 2.3.4
const usz MAX_INBOUND = 65536;         // Conn.feed buffers at most this much unread ciphertext

enum NameKind { DNS, IPV4, IPV6 }

struct NamePlan
{
	NameKind kind;
	String name;     // without the trailing dot
}

fn bool is_digit(char c) => c >= '0' && c <= '9';

fn bool is_hex_digit(char c) => is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');

// Dotted quad: four decimal numbers 0..255 without leading junk.
fn bool is_ipv4_literal(String s)
{
	int parts = 0;
	usz i = 0;
	while (i < s.len)
	{
		usz start = i;
		int value = 0;
		while (i < s.len && is_digit(s[i]))
		{
			value = value * 10 + (s[i] - '0');
			if (value > 255) return false;
			i++;
		}
		if (i == start || i - start > 3) return false;
		parts++;
		if (i == s.len) break;
		if (s[i] != '.') return false;
		i++;
		if (i == s.len) return false;
	}
	return parts == 4;
}

// Only the characters of an IPv6 literal; the precise grammar is checked by OpenSSL when the address is set.
fn bool is_ipv6_literal(String s)
{
	if (s.len < 2 || s.len > 45) return false;
	bool colon = false;
	foreach (c : s)
	{
		if (c == ':')
		{
			colon = true;
		}
		else if (!is_hex_digit(c) && c != '.')
		{
			return false;
		}
	}
	return colon;
}

// Validates the verification/SNI name before any OpenSSL call: non-empty, at most 253 bytes, no NUL or control
// bytes, ASCII only (callers pass the A-label for internationalised names), one trailing dot stripped, no empty
// labels (leading dot, `..`), labels of at most 63 bytes. IP literals are classified here.
fn NamePlan? validate_server_name(String name)
{
	if (name.len == 0) return CONFIG_INVALID~;
	foreach (c : name)
	{
		if (c <= 0x20 || c >= 0x7f) return CONFIG_INVALID~;
	}
	if (is_ipv6_literal(name)) return { IPV6, name };
	String n = name;
	if (n[n.len - 1] == '.') n = n[:n.len - 1];
	if (n.len == 0 || n.len > MAX_HOSTNAME_LEN) return CONFIG_INVALID~;
	usz label = 0;
	foreach (c : n)
	{
		if (c == '.')
		{
			if (label == 0) return CONFIG_INVALID~;
			label = 0;
			continue;
		}
		bool ok = is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_';
		if (!ok) return CONFIG_INVALID~;
		if (++label > MAX_LABEL_LEN) return CONFIG_INVALID~;
	}
	if (label == 0) return CONFIG_INVALID~;
	if (is_ipv4_literal(n)) return { IPV4, n };
	return { DNS, n };
}

// Effective protocol versions: DEFAULT means TLS 1.2 as the floor and TLS 1.3 as the ceiling.
fn int ClientConfig.min_wire(&self) => self.min_version == DEFAULT ? Version.TLS_1_2.wire : self.min_version.wire;
fn int ClientConfig.max_wire(&self) => self.max_version == DEFAULT ? Version.TLS_1_3.wire : self.max_version.wire;

// Checks option combinations. Every violation is CONFIG_INVALID.
fn void? ClientConfig.validate(&self)
{
	if (self.pin_sha256.len != 0 && self.pin_sha256.len != 32) return CONFIG_INVALID~;
	if (self.verify == PINNED_ONLY && self.pin_sha256.len == 0) return CONFIG_INVALID~;
	if ((self.client_cert_file.len == 0) != (self.client_key_file.len == 0)) return CONFIG_INVALID~;
	if (self.min_wire() > self.max_wire()) return CONFIG_INVALID~;
	if (self.max_chain_depth < 0) return CONFIG_INVALID~;
	// an empty or oversized protocol name is a bad ALPN list
	if (catch err = wire::encode_alpn(self.alpn, tmem)) return CONFIG_INVALID~;
}
