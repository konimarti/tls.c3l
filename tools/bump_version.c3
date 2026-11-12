// Sets the version of this library in the two places that must agree: "version" in project.json and the constant
// VERSION in tls.c3. Run from the repository root:
//
//     c3c compile-run tools/bump_version.c3 -- 0.2.0
//
// Nothing is written unless the argument is MAJOR.MINOR.PATCH and each of the two patterns occurs exactly once.
module bump_version;

import std::io, std::io::file;

const String[2] FILES = { "project.json", "tls.c3" };
const String[2] PREFIXES = { "\"version\": \"", "const String VERSION = \"" };

fn bool valid_version(String v)
{
	int parts = 0;
	usz digits = 0;
	foreach (c : v)
	{
		if (c >= '0' && c <= '9')
		{
			digits++;
		}
		else if (c == '.' && digits > 0 && parts < 2)
		{
			parts++;
			digits = 0;
		}
		else
		{
			return false;
		}
	}
	return parts == 2 && digits > 0;
}

// How often `needle` occurs in `text`, and where it first does.
fn usz count(String text, String needle, usz* first)
{
	usz n = 0;
	for (usz i = 0; i + needle.len <= text.len; i++)
	{
		if (text[i:needle.len] == needle)
		{
			if (n == 0) *first = i;
			n++;
		}
	}
	return n;
}

// The whole line of `text` that contains offset `at`.
fn String line_at(String text, usz at)
{
	usz start = at;
	while (start > 0 && text[start - 1] != '\n') start--;
	usz end = at;
	while (end < text.len && text[end] != '\n') end++;
	return text[start:end - start];
}

fn int main(String[] args)
{
	if (args.len != 2 || !valid_version(args[1]))
	{
		io::eprintn("usage: bump_version MAJOR.MINOR.PATCH (digits only), run from the repository root");
		return 1;
	}
	String version = args[1];
	String[2] texts;
	usz[2] at;
	for (usz k = 0; k < 2; k++)
	{
		char[]? data = file::load_temp(FILES[k]);
		if (catch err = data)
		{
			io::eprintfn("cannot read %s: %s", FILES[k], err);
			return 1;
		}
		texts[k] = (String)data;
		usz n = count(texts[k], PREFIXES[k], &at[k]);
		if (n != 1)
		{
			io::eprintfn("%s: expected exactly one `%s`, found %d: nothing written", FILES[k], PREFIXES[k], n);
			return 1;
		}
	}
	String[2] updated;
	for (usz k = 0; k < 2; k++)
	{
		usz from = at[k] + PREFIXES[k].len;
		usz to = from;
		while (to < texts[k].len && texts[k][to] != '"') to++;
		if (to >= texts[k].len)
		{
			io::eprintfn("%s: the version is not closed by a quote: nothing written", FILES[k]);
			return 1;
		}
		updated[k] = texts[k][:from].tconcat(version).tconcat(texts[k][to..]);
	}
	for (usz k = 0; k < 2; k++)
	{
		if (catch err = file::save(FILES[k], updated[k]))
		{
			io::eprintfn("cannot write %s: %s", FILES[k], err);
			return 1;
		}
		io::printfn("%s: %s", FILES[k], line_at(updated[k], at[k]).trim());
	}
	return 0;
}
