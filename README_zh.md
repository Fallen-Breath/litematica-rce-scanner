# litematica-rce-scanner

[![License](https://img.shields.io/github/license/Fallen-Breath/litematica-rce-scanner.svg)](http://www.gnu.org/licenses/gpl-3.0.html)
[![Issues](https://img.shields.io/github/issues/Fallen-Breath/litematica-rce-scanner.svg)](https://github.com/Fallen-Breath/litematica-rce-scanner/issues)
[![Docker](https://img.shields.io/docker/v/fallenbreath/litematica-rce-scanner/latest?label=DockerHub)](https://hub.docker.com/r/fallenbreath/litematica-rce-scanner)

[English](README.md) | 中文

一个用于检测存在风险的 [Litematica](https://github.com/sakura-ryoko/litematica) 与 [Servux](https://github.com/sakura-ryoko/servux) jar 文件的小型命令行扫描器。

它可以扫描一个或多个路径，报告检测到的 Litematica/Servux jar，并标记存在漏洞的版本，方便删除或升级。

![snapshot](snapshot.png)

## 使用方式

```bash
litematica-rce-scanner [options] [path ...]
```

如果没有提供路径，则默认扫描当前目录。

常用参数：

```text
-j, -concurrency int     并发扫描的文件数量，默认 1
-csv path                将检测到的 Litematica/Servux jar 结果写入 CSV 文件
-color value             颜色输出：auto、always、never，默认 auto
-progress                向 stdout 定期输出进度，默认 true
-warnings                输出逐文件扫描发生失败时的 warning，默认 false
-non-recursive           只扫描每个目录下的直接文件，不递归进入子目录
-fail-on-vulnerable      找到存在漏洞的 jar 时以退出码 1 退出
-version                 输出版本号并退出
```

使用 `-progress=false` 可以关闭进度输出。
使用 `-non-recursive` 可以只扫描每个目标目录下的直接文件。位置参数如果是文件路径，会直接扫描该文件。
使用 `-warnings` 可以输出 permission denied 等逐文件 warning。未设置该参数时，warning 不逐条输出，但仍会计入 summary。

示例：

```bash
./litematica-rce-scanner
./litematica-rce-scanner -j 8 /path/to/mods /another/path
./litematica-rce-scanner -non-recursive ./mods
./litematica-rce-scanner ./mods/litematica.jar
./litematica-rce-scanner -csv results.csv -fail-on-vulnerable ./mods
```

Windows 下可以把一个或多个目录拖到 `.exe` 上运行。程序在 Windows 交互式控制台中、且没有显式命令行 flag 时，会在结束后等待回车，避免控制台窗口立刻关闭。可使用 `-no-pause` 关闭该行为。

## 输出

命令行输出始终为英文。交互式终端默认启用 ANSI 颜色，现代 Windows 终端也支持。

扫描时会向 stdout 每 5 秒输出一次进度，第一次大约在开始扫描 5 秒后输出。扫描结束后会再输出一次最终进度：

```text
Progress: scanned 123 files, elapsed 12.3s, vulnerable 7
```

扫描器不会预扫整棵目录树，也不会把所有路径都放进内存；它会一边遍历一边扫描，并使用很小的有界任务队列。

检测到的 Litematica 和 Servux jar 会在扫描过程中实时输出。存在漏洞的 jar 标记为 `[VULNERABLE]`；命中目标 class 但不满足漏洞构造函数规则的 jar 标记为 `[SAFE]`。

```text
[VULNERABLE]  path/to/file.jar   litematica v1.2.3
[SAFE]        path/to/file.jar   servux
```

`version` 字段会尽量从 `fabric.mod.json` 中读取。如果 manifest 或版本读取失败，则省略版本字段。

启用 CSV 输出时，包含这些列：

```text
path,mod,status,version
```

CSV 只记录检测到的 Litematica/Servux jar。

## 检测方式

扫描器会遍历指定路径下的普通文件。默认会递归扫描目录；使用 `-non-recursive` 时，只扫描每个目标目录下的直接文件。扫描不依赖文件扩展名。

只有当文件是合法 ZIP/JAR，并且 ZIP 中央目录包含以下任一精确 class 路径时，才会作为候选 jar 继续检查：

- `fi/dy/masa/litematica/schematic/transmit/SchematicBuffer.class`
- `fi/dy/masa/servux/schematic/transmit/SchematicBuffer.class`

扫描器会先检查 ZIP 最小大小和 local file header magic，再通过 Go 标准库 `archive/zip` 读取 ZIP 结束记录和中央目录，因此不会解压整个压缩包。命中后，只会解压目标 `SchematicBuffer.class`。

如果目标 `SchematicBuffer.class` 中所有构造函数的首个参数都是 `java.lang.String`，则报告该 jar 存在漏洞。class parser 会直接检查 method table：

- 方法名必须是 `<init>`
- 方法 descriptor 必须存在首个参数
- 首个参数必须是 `Ljava/lang/String;`
- 所有构造函数都满足该规则时，该 jar 才会报告为存在漏洞

如果目标 class 无法读取或解析，会计入错误数量，而不会报告为存在漏洞。使用 `-warnings` 可以输出逐文件详情。

## Docker

该扫描器也可以以容器形式执行。镜像在 Docker Hub 和 GHCR 均可用。

下面的命令会用默认参数，单线程递归扫描当前路径下的全部文件：

```bash
docker run --rm -t -v "$PWD:/scan:ro" fallenbreath/litematica-rce-scanner:latest
docker run --rm -t -v "$PWD:/scan:ro" ghcr.io/fallen-breath/litematica-rce-scanner:latest
```

镜像默认以 root 身份运行，方便扫描宿主机挂载进容器后权限较严格的本地文件。
