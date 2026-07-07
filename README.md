# litematica-rce-scanner

[![License](https://img.shields.io/github/license/Fallen-Breath/litematica-rce-scanner.svg)](http://www.gnu.org/licenses/gpl-3.0.html)
[![Issues](https://img.shields.io/github/issues/Fallen-Breath/litematica-rce-scanner.svg)](https://github.com/Fallen-Breath/litematica-rce-scanner/issues)
[![Docker](https://img.shields.io/docker/v/fallenbreath/litematica-rce-scanner/latest?label=DockerHub)](https://hub.docker.com/r/fallenbreath/litematica-rce-scanner)

English | [中文](README_zh.md)

A lightweight command-line scanner that detects vulnerable [Litematica](https://github.com/sakura-ryoko/litematica) and [Servux](https://github.com/sakura-ryoko/servux) jar files.

It scans one or more specified paths, identifies Litematica/Servux jars, and flags vulnerable versions so you can remove or upgrade them promptly.

![snapshot](snapshot.png)

## Usage

Windows TL;DR: put the `.exe` in the directory you want to scan, then double-click it.

```bash
litematica-rce-scanner [options] [path ...]
```

If no path is given, the scanner defaults to the current directory.

Common options:

```text
-j, -concurrency int      number of files to scan concurrently (default 1)
-csv path                 write detected Litematica/Servux jar results to a CSV file
-color value              color output mode: auto, always, never (default auto)
-progress                 print periodic progress to stdout (default true)
-warnings                 print per-file warnings for scan failures (default false)
-non-recursive            scan only immediate files under each directory, do not recurse into subdirectories
-jar-only                 scan only files whose name contains .jar
-fail-on-vulnerable       exit with code 1 if any vulnerable jar is found
-version                  print version information and exit
```

Set `-progress=false` to suppress progress output.
Set `-non-recursive` to scan only files directly inside each specified directory. File paths passed as arguments are scanned directly.
Set `-jar-only` to scan only files whose name contains `.jar`; names such as `mod.jar.disabled` are still included.
Set `-warnings` to show per-file warnings such as permission-denied errors.

Examples:

```bash
./litematica-rce-scanner
./litematica-rce-scanner -j 8 /path/to/mods /another/path
./litematica-rce-scanner -non-recursive ./mods
./litematica-rce-scanner -jar-only ./mods
./litematica-rce-scanner ./mods/litematica.jar
./litematica-rce-scanner -warnings /
./litematica-rce-scanner -csv results.csv -fail-on-vulnerable ./mods
```

On Windows, you can drag one or more folders onto the `.exe` file to launch it. When run in an interactive Windows console without explicit command-line flags, the program will pause and wait for Enter before exiting, preventing the console window from closing immediately. Use `-no-pause` to disable this behavior.

## Output

Terminal output is in English. Color is enabled automatically when supported.

During scanning, progress is printed to stdout every 5 seconds, with the first update appearing approximately 5 seconds after startup. A final progress line is shown after scanning completes:

```text
Progress: scanned 123 files, elapsed 12.3s, vulnerable 7
```

Detected Litematica and Servux jars are reported in real time as they are scanned. Vulnerable jars are marked `[VULNERABLE]`, while jars that match the target class but do not satisfy the vulnerable constructor rule are marked `[SAFE]`.

```text
[VULNERABLE]  path/to/file.jar   litematica v1.2.3
[SAFE]        path/to/file.jar   servux
```

The mod version is shown when available. If it cannot be read, it is omitted.

If vulnerable jars are found, the final summary asks you to update the affected mods as soon as possible and prints Modrinth version pages for Litematica and Servux.

When CSV output is enabled, the file contains the following columns:

```text
path,mod,status,version
```

Only detected Litematica or Servux jars are written to the CSV.

## Detection Details

The scanner checks regular files under the specified paths. Directory scanning is recursive by default; using `-non-recursive` limits it to immediate files within each target directory.

A file is considered relevant only if it is a valid JAR/ZIP archive containing one of these class entries:

- `fi/dy/masa/litematica/schematic/transmit/SchematicBuffer.class`
- `fi/dy/masa/servux/schematic/transmit/SchematicBuffer.class`

The scanner does not rely on file extensions unless `-jar-only` is used. Matching archives are checked without extracting the whole file.

A jar is reported as vulnerable when every constructor in the target `SchematicBuffer.class` has `java.lang.String` as its first parameter.

If the target class cannot be checked, it is counted as an error rather than being reported as vulnerable. Use `-warnings` to show detailed per-file error information.

## Docker

The scanner can also be run as a container. Images are available on both Docker Hub and GHCR.

The following commands scan all files under the current directory recursively, using default single-threaded settings:

```bash
docker run --rm -t -v "$PWD:/scan:ro" fallenbreath/litematica-rce-scanner:latest
docker run --rm -t -v "$PWD:/scan:ro" ghcr.io/fallen-breath/litematica-rce-scanner:latest
```

The container runs as root by default, which is helpful for scanning mounted local files that have restrictive ownership or permission settings.
