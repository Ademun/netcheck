# netcheck - Simple Network Port Scanner in Go

![Go Version](https://img.shields.io/badge/go-1.18%2B-blue)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

`netcheck` is a minimalist network port scanner implementing basic TCP scanning functionality. Created for educational purposes and to demonstrate network programming principles in Go.

## Features

- 📡 TCP Connect port scanning
- 🔢 Port range support (`80,443,1000-2000`)
- ⚡ Parallel scanning with thread limiting

## Report Export

The tool supports exporting scan results in multiple formats for further analysis:

- **JSON**: Structured format for programmatic processing
- **CSV**: Tabular format for spreadsheets and databases

To generate reports:
```bash
# JSON report
netcheck example.com -o json

# CSV report
netcheck example.com -o csv
```
Report files are automatically named using the timestamp pattern YYYY-MM-DD HH-MM.format

**Key features:**

- Preserves all scan metadata (target, timestamps, scanner version)

- Retains service banners and port statuses

- Compatible with SIEM systems and data analysis tools

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/netcheck.git
   cd netcheck
   ```

2. Build the binary:
   ```bash
   go build -o netcheck cmd/main.go
   ```


## Usage

Basic syntax:
```bash
netcheck [FLAGS] TARGET
```

### Command Examples:

Scan specific ports:
```bash
netcheck -p 80,443,8080 example.com 
```

Scan port range:
```bash
netcheck -p 1-100 example.com
```

Scan all ports showing closed ones:
```bash
netcheck -v example.com
```

### Flags:
| Flag       | Description                          | Default      |
|------------|-------------------------------------|--------------|
| `-p`, `--ports` | Ports to scan                      | All (0-65535)|
| `-v`, `--verbose` | Show closed ports                 | `false`      |


## Limitations

- Only TCP Connect scanning method implemented
- No service detection

## Roadmap

Planned improvements:
- Implement SYN scanning
- Add UDP protocol support
- Service version detection
- Configurable timeouts via flags

## License

Project distributed under MIT license. See [LICENSE](LICENSE) for details.

---

> **Note:** This tool is intended for legal use only. Always obtain explicit permission before scanning networks.