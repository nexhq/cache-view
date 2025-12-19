# cache-view

**Expert Browser Forensics & Recovery Tool**

Recover images, videos, and evidence from browser cache directories (Chrome, Edge, Firefox). Features **deep file carving** for binary blobs, **source URL mapping**, smart filtering, and automatic evidence reporting.

## Features

- **Multi-Browser Support**: Chrome, Edge, Firefox (and custom paths).
- **Format Support**: Images (JPG, PNG, GIF, WEBP, BMP, ICO) and Videos (MP4, WEBM).
- **Deep File Carving**: Scans and extracts hundreds of images hidden inside binary data blobs (`data_` files) using signature analysis.
- **Source URL Mapping**: Recovers the original source URL for cached files where possible.
- **Smart Filtering**: Filter by file size, dimensions (width/height), and modification date.
- **Duplicate Removal**: Automatically skips duplicate files using SHA256 hashing.
- **Structured Output**:  Optionally organize files by type (`images/`, `videos/`) or extension (`png/`, `jpg/`).
- **Reporting**: Generates a forensic `gallery.html` for instant viewing and a `recovery_report.csv` with metadata.
- **User Experience**: Live progress bars for scanning and carving.
- **Cross-Platform**: Works on Windows, macOS, and Linux.

## Installation

```bash
nex install cache-view
```
*Dependencies: `Pillow`, `tqdm`, `colorama` (automatically installed)*

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
| `--carve` | Enable deep file carving for binary blobs (Slow but thorough). | `False` |
| `--min-size` | Minimum file size in KB. | 1 KB |
| `--min-width` | Minimum image width in pixels. | 0 (All) |
| `--days` | Only recover files from the last N days. | All time |
| `--rename-hash` | Rename files to SHA256 content hash. | `False` |
| `--no-video` | Skip video recovery. | Videos included |
| `--verbose`, `-v` | Enable verbose logging (disables progress bar). | `False` |

### Examples

**Standard Scan (Organized by Extension)**
Recover files from Chrome and organize them into `images/png`, `images/jpg`, etc.
```bash
python main.py
```

**Recover Recent Photos (Last 24h, Flat Structure)**
Recover all images/videos from the last day into a single folder.
```bash
python main.py --days 1 --structure flat --output recent_photos
```

**High-Res Image Recovery (Edge)**
Recover only images at least 800px wide from Edge.
```bash
python main.py --browser edge --min-width 800
```

**Forensic Archive Mode**
Recover from a custom path, rename files to their SHA256 hash, and produce a report.
```bash
python main.py --path "C:\Backups\User\Cache" --rename-hash --output evidence_locker
```

**Deep Scan (File Carving)**
Scan binary blobs to recover embedded images that don't exist as separate files.
```bash
python main.py --carve --min-size 5
```

## Output

The tool creates the following in the output directory:
1. **Recovered Files**: Organized according to your `--structure` setting.
2. **gallery.html**: A local webpage to view all recovered content in a grid.
3. **recovery_report.csv**: Detailed log of original names, hashes, and timestamps.

## License

MIT
