# recursive-search BOF

Recursively list files that match a wildcard pattern from Beacon.

## What it does
- Walks the target directory tree and matches filenames with `*` and `?` wildcards; matching is case-insensitive.
- If you provide a bare substring (no wildcards), it wraps it as `*substring*` automatically.
- Aggregates all matches into one output block; prints a summary if none are found.

## Usage in Beacon
1. Load `x64/Release/recursive-search.cna` in Cobalt Strike with `recursive-search.x64.o` in the same folder (already present).
2. Run `recursive-search <Directory> <Pattern>` (ASCII strings). Examples: `recursive-search C:\Logs\ *.ps1`, `recursive-search C:\Users\ passw????.txt`, `recursive-search C:\ *.pfx`.
3. Results are returned in a single inline execute output for easy copy.

## Build notes
- Open `recursive-search.sln` in Visual Studio 2022 and build `Release | x64`.
- The build emits `x64/Release/recursive-search.x64.o`; the Aggressor script expects `recursive-search.<arch>.o` next to the `.cna`.
