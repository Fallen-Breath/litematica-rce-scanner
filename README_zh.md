# litematica-rce-scanner

[![License](https://img.shields.io/github/license/Fallen-Breath/litematica-rce-scanner.svg)](http://www.gnu.org/licenses/gpl-3.0.html)
[![Issues](https://img.shields.io/github/issues/Fallen-Breath/litematica-rce-scanner.svg)](https://github.com/Fallen-Breath/litematica-rce-scanner/issues)
[![Docker](https://img.shields.io/docker/v/fallenbreath/litematica-rce-scanner/latest?label=DockerHub)](https://hub.docker.com/r/fallenbreath/litematica-rce-scanner)

[English](README.md) | 中文

一款轻量级命令行扫描工具，用于检测存在安全风险的 [Litematica](https://github.com/sakura-ryoko/litematica) 与 [Servux](https://github.com/sakura-ryoko/servux) 的 jar 文件。

该工具可扫描一个或多个路径，识别出相关的 Litematica/Servux jar 文件，并标记出存在漏洞的版本，方便您及时删除或升级。

![snapshot](snapshot.png)

## 使用方法

Windows 环境太长不看版用法：把 `.exe` 放到要扫描的目录里，双击打开即可。

```bash
litematica-rce-scanner [options] [path ...]
```

若未指定路径，则默认扫描当前目录。

常用参数说明：

```text
-j, -concurrency int     并发扫描的文件数量，默认为 1
-csv path                将检测到的 Litematica/Servux jar 信息写入指定的 CSV 文件
-color value             颜色输出模式：auto、always、never，默认为 auto
-progress                是否向 stdout 定期输出进度信息，默认为 true
-warnings                是否输出逐文件扫描失败时的警告信息，默认为 false
-non-recursive           仅扫描每个目录下的直接文件，不递归进入子目录
-jar-only                仅扫描文件名包含 .jar 的文件
-fail-on-vulnerable      若发现存在漏洞的 jar 文件，则以退出码 1 退出
-version                 输出版本号并退出
```

使用 `-progress=false` 可关闭进度输出。
使用 `-non-recursive` 可限制扫描范围，仅处理每个目标目录下的直接文件。若位置参数为文件路径，则直接扫描该文件。
使用 `-jar-only` 可仅扫描文件名包含 `.jar` 的文件；例如 `mod.jar.disabled` 仍会被扫描。
使用 `-warnings` 可输出诸如权限不足等逐文件的警告信息。

示例：

```bash
./litematica-rce-scanner
./litematica-rce-scanner -j 8 /path/to/mods /another/path
./litematica-rce-scanner -non-recursive ./mods
./litematica-rce-scanner -jar-only ./mods
./litematica-rce-scanner ./mods/litematica.jar
./litematica-rce-scanner -warnings /
./litematica-rce-scanner -csv results.csv -fail-on-vulnerable ./mods
```

在 Windows 下，您可以将一个或多个目录直接拖拽到 `.exe` 文件上运行。若程序运行在 Windows 交互式控制台中，且未使用任何命令行参数，则会在执行结束后暂停并等待回车，防止控制台窗口立即关闭。可通过 `-no-pause` 禁用此行为。

## 输出说明

命令行输出内容为英文。支持时会自动启用颜色。

扫描期间，程序会每隔 5 秒向 stdout 输出一次进度，首次进度显示大约在扫描启动 5 秒后出现。扫描完成后，还会再输出一次最终进度信息：

```text
Progress: scanned 123 files, elapsed 12.3s, vulnerable 7
```

检测到的 Litematica 和 Servux jar 文件会在扫描过程中实时输出。其中，存在漏洞的 jar 标记为 `[VULNERABLE]`，而命中目标 class 但不满足漏洞构造函数规则的 jar 标记为 `[SAFE]`。

```text
[VULNERABLE]  path/to/file.jar   litematica v1.2.3
[VULNERABLE]  path/to/dev.jar    litematica v1.2.3 (dev remap)
[SAFE]        path/to/file.jar   servux
```

能够读取到 mod 版本时会一并显示；读取不到时会省略。

黄色的 `(dev remap)` 标识表示该 jar 看起来像 Fabric 开发环境中的 remapped jar。它通常没有正常运行环境里的 mod jar 那么紧急，但仍建议确认不要误发布或部署。

如果发现存在漏洞的 jar，最终 summary 会提示尽快更新受影响的 mod，并输出 Litematica 与 Servux 的 Modrinth 版本页面。

启用 CSV 输出时，生成的文件将包含以下列：

```text
path,mod,status,version
```

CSV 中仅记录检测到的 Litematica 或 Servux jar 文件。

## 检测原理

扫描器会检查指定路径下的普通文件。默认会递归扫描所有子目录；若使用 `-non-recursive` 参数，则仅扫描每个目标目录下的直接文件。

仅当文件是合法的 JAR/ZIP 压缩包，且包含以下任一精确 class 路径时，才会进入后续检查：

- `fi/dy/masa/litematica/schematic/transmit/SchematicBuffer.class`
- `fi/dy/masa/servux/schematic/transmit/SchematicBuffer.class`

除非使用 `-jar-only`，否则扫描过程不依赖文件扩展名。命中目标的压缩包会被检查，但不会整体解压。

若目标 `SchematicBuffer.class` 中所有构造函数的首个参数均为 `java.lang.String`，则判定该 jar 存在漏洞。

若目标 class 无法检查，则该文件会被计入错误数量，但不会报告为存在漏洞。启用 `-warnings` 后可输出逐文件的详细错误信息。

## Docker 支持

本扫描器也支持以容器方式运行，镜像已上传至 Docker Hub 和 GHCR。

以下命令将以默认参数、单线程递归扫描当前目录下的全部文件：

```bash
docker run --rm -t -v "$PWD:/scan:ro" fallenbreath/litematica-rce-scanner:latest
docker run --rm -t -v "$PWD:/scan:ro" ghcr.io/fallen-breath/litematica-rce-scanner:latest
```

镜像默认以 root 用户身份运行，便于扫描宿主机挂载进容器后权限设置较为严格的本地文件。
