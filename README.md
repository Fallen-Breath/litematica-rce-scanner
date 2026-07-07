# litematica-rce-scanner

English | [中文](README_zh.md)

A small command-line scanner for detecting vulnerable [Litematica](https://github.com/sakura-ryoko/litematica) and [Servux](https://github.com/sakura-ryoko/servux) jar files.

It scans one or more paths, reports detected Litematica/Servux jars, and marks vulnerable versions so they can be removed or upgraded.

## Usage

```bash
litematica-rce-scanner [options] [path ...]
```

If no path is provided, the scanner uses the current directory.

Common options:

```text
-j, -concurrency int      number of files to scan concurrently (default 1)
-csv path                write detected Litematica/Servux jar results to a CSV file
-color value             color output: auto, always, never (default auto)
-progress                print periodic progress to stdout (default true)
-warnings                print per-file warnings for scan failures (default false)
-fail-on-vulnerable      exit with code 1 when vulnerable jars are found
-version                 print version and exit
```

Use `-progress=false` to disable progress output.
Use `-warnings` to print per-file warnings such as permission-denied files. Warnings are still counted in the summary when this flag is not set.

Examples:

```bash
litematica-rce-scanner .
litematica-rce-scanner -j 8 /path/to/mods /another/path
litematica-rce-scanner -csv results.csv -fail-on-vulnerable ./mods
```

On Windows, you can drag one or more folders onto the `.exe`. When the program is launched without explicit flags in an interactive Windows console, it waits for Enter before exiting so the result window does not close immediately. Use `-no-pause` to disable this behavior.

## Output

The terminal output is always English. ANSI color is enabled automatically for interactive terminals, including modern Windows terminals.

During scanning, progress is printed to stdout every 5 seconds, starting about 5 seconds after scanning begins. A final progress line is printed after scanning completes:

```text
Progress: scanned 123 files, elapsed 12.3s, vulnerable 7
```

The scanner does not pre-scan the tree or keep every path in memory; it walks and scans concurrently with a small bounded work queue.

Detected Litematica and Servux jars are printed as they are scanned. Vulnerable jars are marked `[VULNERABLE]`; matching jars that do not satisfy the vulnerable constructor rule are marked `[SAFE]`.

```text
[VULNERABLE] path/to/file.jar | litematica v1.2.3
[SAFE] path/to/file.jar | servux
```

The `version` field is read from `fabric.mod.json` when available. If the manifest or version cannot be read, the version field is omitted.

The CSV file, when enabled, contains these columns:

```text
path,mod,status,version
```

Only detected Litematica/Servux jars are written to the CSV.

## Detection Details

The scanner recursively walks all regular files under the requested paths. It does not rely on file extensions.

A file is treated as a candidate only when it is a valid ZIP/JAR and the ZIP central directory contains one of these exact class entries:

- `fi/dy/masa/litematica/schematic/transmit/SchematicBuffer.class`
- `fi/dy/masa/servux/schematic/transmit/SchematicBuffer.class`

The scanner first checks the minimum ZIP size and local file header magic, then reads the ZIP end record and central directory through Go's `archive/zip` reader. It does not decompress whole archives. For matching jars, it decompresses only the target `SchematicBuffer.class`.

A jar is reported as vulnerable when every constructor in the target `SchematicBuffer.class` has `java.lang.String` as its first parameter. The class parser inspects the method table directly:

- method name must be `<init>`
- method descriptor must have a first parameter
- that first parameter must be `Ljava/lang/String;`
- all constructors must satisfy that rule for the jar to be reported as vulnerable

If the target class cannot be read or parsed, it is counted as an error rather than vulnerable. Use `-warnings` to print per-file details.

## Docker

```bash
docker run --rm -t -v "$PWD:/scan:ro" fallenbreath/litematica-rce-scanner:latest
docker run --rm -t -v "$PWD:/scan:ro" ghcr.io/fallen-breath/litematica-rce-scanner:latest
```

The image runs as root by default, which makes it practical for scanning mounted local files with restrictive ownership or mode bits.
