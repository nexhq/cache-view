# cache-view

**Advanced Browser Forensics & Recovery Tool**

Recover images and videos from browser cache directories (Chrome, Edge, Firefox). Features smart filtering, duplicate removal, structured organization, and automatic gallery generation.

## Features

- **Multi-Browser Support**: Chrome, Edge, Firefox (and custom paths).
- **Format Support**: Images (JPG, PNG, GIF, WEBP, BMP, ICO) and Videos (MP4, WEBM).
- **Smart Filtering**: Filter by file size, dimensions (width/height), and modification date.
- **Duplicate Removal**: Automatically skips duplicate files using SHA256 hashing.
- **Structured Output**:  Optionally organize files by type (`images/`, `videos/`) or extension (`png/`, `jpg/`).
- **Reporting**: Generates a modern `gallery.html` for instant viewing and a `recovery_report.csv` for forensic analysis.
- **User Experience**: Includes progress bars and colored terminal output.
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

## Output

The tool creates the following in the output directory:
1. **Recovered Files**: Organized according to your `--structure` setting.
2. **gallery.html**: A local webpage to view all recovered content in a grid.
3. **recovery_report.csv**: Detailed log of original names, hashes, and timestamps.

## License

MIT
