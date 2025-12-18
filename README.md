# cache-view

**Advanced Browser Forensics & Recovery Tool**

Recover images and videos from browser cache directories (Chrome, Edge, Firefox). Features smart filtering, duplicate removal, and automatic gallery generation.

## Features

- **Multi-Browser Support**: Chrome, Edge, Firefox (and custom paths).
- **Format Support**: Images (JPG, PNG, GIF, WEBP, BMP, ICO) and Videos (MP4, WEBM).
- **Smart Filtering**: Filter by file size, dimensions (width/height), and modification date.
- **Duplicate Removal**: Automatically skips duplicate files using SHA256 hashing.
- **Reporting**: Generates a `gallery.html` for instant viewing and a `recovery_report.csv` for forensic analysis.
- **Cross-Platform**: Works on Windows, macOS, and Linux.

## Installation

```bash
nex install cache-view
```
*Note: This tool requires `Pillow` for image analysis.*

## Usage

```bash
nex run cache-view [OPTIONS]
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `--browser` | Target browser: `chrome`, `edge`, `firefox`, `custom`. | `chrome` |
| `--path` | Custom cache path (use with `custom`). | Auto-detected |
| `--output`, `-o` | Output directory. | `recovered_data` |
| `--structure` | Output organization: `flat`, `type` (images/videos), `ext` (images/png). | `ext` |
| `--min-size` | Minimum file size in KB. | 1 KB |
| `--min-width` | Minimum image width in pixels. | 0 (All) |
| `--days` | Only recover files from the last N days. | All time |
| `--rename-hash` | Rename files to SHA256 content hash. | `False` |
| `--no-video` | Skip video recovery. | Videos included |

### Examples

**Standard Scan (Organized by Extension):**
```bash
python main.py
# Creates: recovered_data/images/png/image.png, etc.
```

**Recover Recent Photos (Last 24h, Flat Structure):**
```bash
python main.py --days 1 --structure flat --output recent_photos
```

## Output

The tool creates the following in the output directory:
1. **Recovered Files**: The actual images and videos.
2. **gallery.html**: A local webpage to view all recovered content in a grid.
3. **recovery_report.csv**: Detailed log of original names, hashes, and timestamps.

## License

MIT
