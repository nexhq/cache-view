#!/usr/bin/env python3
"""
cache-view - Browser Forensics & Recovery Tool
Recovers images and videos from browser cache directories with advanced filtering, 
structured organization, and detailed reporting.
"""

import os
import sys
import argparse
import shutil
import hashlib
import platform
from pathlib import Path
from datetime import datetime, timedelta

# Third-party libraries
try:
    from PIL import Image
    from tqdm import tqdm
    from colorama import init, Fore, Style
except ImportError:
    print("Error: Missing dependencies. Please run 'pip install -r requirements.txt'")
    sys.exit(1)

# Initialize colorama
init(autoreset=True)

# Magic numbers for file formats
SIGNATURES = {
    # Images
    b'\xFF\xD8\xFF': 'jpg',
    b'\x89\x50\x4E\x47': 'png',
    b'\x47\x49\x46\x38': 'gif',
    b'\x42\x4D': 'bmp',
    b'\x00\x00\x01\x00': 'ico',
    # Videos
    b'\x00\x00\x00\x18\x66\x74\x79\x70': 'mp4',
    b'\x00\x00\x00\x20\x66\x74\x79\x70': 'mp4',
    b'\x00\x00\x00\x14\x66\x74\x79\x70': 'mp4',
    b'\x1A\x45\xDF\xA3': 'webm',
}

WEBP_RIFF = b'RIFF'
WEBP_WEBP = b'WEBP'

TYPE_MAP = {
    'jpg': 'images', 'png': 'images', 'gif': 'images', 'bmp': 'images', 
    'ico': 'images', 'webp': 'images',
    'mp4': 'videos', 'webm': 'videos'
}

class CacheRecoverer:
    def __init__(self, browser='chrome', custom_path=None, output_dir='recovered_data', 
                 min_size_kb=0, days=None, min_width=0, min_height=0, 
                 rename_hash=False, include_videos=True, verbose=False, sort_by='ext'):
        self.browser = browser
        self.custom_path = custom_path
        self.output_dir = Path(output_dir)
        self.min_size_bytes = min_size_kb * 1024
        self.cutoff_date = datetime.now() - timedelta(days=days) if days else None
        self.min_width = min_width
        self.min_height = min_height
        self.rename_hash = rename_hash
        self.include_videos = include_videos
        self.verbose = verbose
        self.sort_by = sort_by  # 'flat', 'ext', 'type'
        
        self.seen_hashes = set()
        self.report_data = []

    def get_system_paths(self):
        system = platform.system()
        home = Path.home()
        paths = {}
        
        if system == 'Windows':
            local_app = Path(os.environ.get('LOCALAPPDATA', ''))
            paths = {
                'chrome': local_app / "Google" / "Chrome" / "User Data" / "Default" / "Cache" / "Cache_Data",
                'edge': local_app / "Microsoft" / "Edge" / "User Data" / "Default" / "Cache" / "Cache_Data",
                'firefox': local_app / "Mozilla" / "Firefox" / "Profiles"
            }
        elif system == 'Darwin':
            lib_caches = home / "Library" / "Caches"
            paths = {
                'chrome': lib_caches / "Google" / "Chrome" / "Default" / "Cache" / "Cache_Data",
                'edge': lib_caches / "Microsoft Edge" / "Default" / "Cache" / "Cache_Data",
                'firefox': home / "Library" / "Caches" / "Firefox" / "Profiles"
            }
        elif system == 'Linux':
            cache_home = Path(os.environ.get('XDG_CACHE_HOME', home / ".cache"))
            paths = {
                'chrome': cache_home / "google-chrome" / "Default" / "Cache" / "Cache_Data",
                'edge': cache_home / "microsoft-edge" / "Default" / "Cache" / "Cache_Data",
                'firefox': cache_home / "mozilla" / "firefox"
            }
        return paths

    def resolve_cache_path(self):
        if self.custom_path:
            return Path(self.custom_path)
            
        paths = self.get_system_paths()
        path = paths.get(self.browser)
        
        if self.browser == 'firefox' and path and path.exists():
            for profile in path.glob("*"):
                if (profile / "cache2" / "entries").exists():
                    return profile / "cache2" / "entries"
        return path

    def identify_file_type(self, filepath):
        try:
            with open(filepath, 'rb') as f:
                header = f.read(32)
            
            for sig, ext in SIGNATURES.items():
                if header.startswith(sig):
                    if ext in ['mp4', 'webm', 'mov'] and not self.include_videos:
                        return None
                    return ext
            
            if header.startswith(WEBP_RIFF) and header[8:12] == WEBP_WEBP:
                return 'webp'
            
            if self.include_videos and len(header) > 4 and header[4:8] == b'ftyp':
                 return 'mp4'

        except (PermissionError, OSError):
            pass
        return None

    def calculate_hash(self, filepath):
        sha256_hash = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except OSError:
            return None

    def is_image_large_enough(self, filepath):
        if self.min_width == 0 and self.min_height == 0:
            return True
        try:
            with Image.open(filepath) as img:
                return img.width >= self.min_width and img.height >= self.min_height
        except Exception:
            return True

    def get_destination_folder(self, ext):
        """Determines subfolder based on sort_by strategy."""
        base = self.output_dir
        
        if self.sort_by == 'flat':
            return base
            
        category = TYPE_MAP.get(ext, 'others')
        
        if self.sort_by == 'type':
            # recovered_data/images/
            return base / category
            
        if self.sort_by == 'ext':
            # recovered_data/images/png/
            return base / category / ext
            
        return base

    def process(self):
        print(f"{Fore.CYAN}cache-view v1.0.0{Style.RESET_ALL} - Browser Forensics Tool")
        
        cache_path = self.resolve_cache_path()
        if not cache_path or not cache_path.exists():
            print(f"{Fore.RED}Error: Cache path not found at {cache_path}{Style.RESET_ALL}")
            if cache_path and cache_path.parent.exists():
                print(f"{Fore.YELLOW}Trying parent directory: {cache_path.parent}{Style.RESET_ALL}")
                cache_path = cache_path.parent
            else:
                return

        print(f"Target: {Fore.BLUE}{cache_path}{Style.RESET_ALL}")
        print(f"Output: {Fore.BLUE}{self.output_dir}{Style.RESET_ALL}")
        
        # 1. Pre-scan for progress bar
        print(f"{Fore.YELLOW}Analyzing cache files...{Style.RESET_ALL}")
        files_to_scan = []
        for root, _, files in os.walk(cache_path):
            for file in files:
                if not (file.startswith("index") or file.startswith("data_")):
                    files_to_scan.append(Path(root) / file)

        if not files_to_scan:
            print(f"{Fore.RED}No relevant cache files found.{Style.RESET_ALL}")
            return

        print(f"Found {len(files_to_scan)} potential files. Starting recovery...")
        
        # 2. Processing with Progress Bar
        stats = {'recovered': 0, 'duplicates': 0, 'skipped': 0, 'extensions': {}}
        
        with tqdm(total=len(files_to_scan), unit="file", ncols=80, colour="green") as pbar:
            for file_path in files_to_scan:
                pbar.update(1)
                
                # Size & Date Checks
                try:
                    st = file_path.stat()
                    if st.st_size < self.min_size_bytes:
                        stats['skipped'] += 1
                        continue
                    mtime = datetime.fromtimestamp(st.st_mtime)
                    if self.cutoff_date and mtime < self.cutoff_date:
                        stats['skipped'] += 1
                        continue
                except OSError:
                    continue

                # Identification
                ext = self.identify_file_type(file_path)
                if not ext:
                    stats['skipped'] += 1
                    continue
                
                # Deduplication
                file_hash = self.calculate_hash(file_path)
                if not file_hash or file_hash in self.seen_hashes:
                    stats['duplicates'] += 1
                    continue
                
                # Dimension Check
                if ext in ['jpg', 'png', 'webp', 'bmp']:
                    if not self.is_image_large_enough(file_path):
                        stats['skipped'] += 1
                        continue

                # Copy & Organize
                self.seen_hashes.add(file_hash)
                
                dest_folder = self.get_destination_folder(ext)
                dest_folder.mkdir(parents=True, exist_ok=True)
                
                new_filename = f"{file_hash}.{ext}" if self.rename_hash else f"{file_path.name}.{ext}"
                dest_path = dest_folder / new_filename
                
                try:
                    shutil.copy2(file_path, dest_path)
                    stats['recovered'] += 1
                    stats['extensions'][ext] = stats['extensions'].get(ext, 0) + 1
                    
                    # Store relative path for reporting
                    rel_path = dest_path.relative_to(self.output_dir)
                    
                    self.report_data.append({
                        'original_name': file_path.name,
                        'recovered_name': new_filename,
                        'relative_path': str(rel_path).replace('\\', '/'),
                        'extension': ext,
                        'size_kb': st.st_size // 1024,
                        'hash': file_hash,
                        'timestamp': mtime.isoformat()
                    })
                    
                except OSError:
                    pass

        # Summary
        print(f"\n{Fore.GREEN}--- Recovery Complete ---{Style.RESET_ALL}")
        print(f"Recovered: {Fore.GREEN}{stats['recovered']}{Style.RESET_ALL} files")
        print(f"Duplicates: {Fore.YELLOW}{stats['duplicates']}{Style.RESET_ALL}")
        print(f"Skipped: {Fore.RED}{stats['skipped']}{Style.RESET_ALL}")
        print(f"ByType: {stats['extensions']}")
        
        if stats['recovered'] > 0:
            self.generate_report()
            self.generate_gallery()

    def generate_report(self):
        self.output_dir.mkdir(parents=True, exist_ok=True)
        csv_path = self.output_dir / "recovery_report.csv"
        import csv
        
        try:
            with open(csv_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=['original_name', 'recovered_name', 'relative_path', 'extension', 'size_kb', 'hash', 'timestamp'])
                writer.writeheader()
                writer.writerows(self.report_data)
            print(f"Report: {csv_path}")
        except Exception as e:
            print(f"Report Error: {e}")

    def generate_gallery(self):
        html_path = self.output_dir / "gallery.html"
        
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Cache Recovery Gallery</title>
    <style>
        :root { --bg: #111; --card: #222; --text: #eee; --accent: #3b82f6; }
        body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; margin: 0; padding: 20px; }
        header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px solid #333; padding-bottom: 20px; }
        h1 { margin: 0; font-weight: 300; }
        .stats { font-size: 0.9rem; color: #888; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 20px; }
        .card { background: var(--card); border-radius: 8px; overflow: hidden; transition: transform 0.2s; border: 1px solid #333; aspect-ratio: 1; display: flex; flex-direction: column; }
        .card:hover { transform: translateY(-3px); border-color: var(--accent); }
        .thumb { flex: 1; overflow: hidden; display: flex; align-items: center; justify-content: center; background: #000; }
        img, video { max-width: 100%; max-height: 100%; object-fit: contain; }
        .info { padding: 10px; font-size: 0.8rem; background: #2a2a2a; border-top: 1px solid #333; }
        .info div { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
        .tag { display: inline-block; padding: 2px 6px; background: #333; border-radius: 4px; font-size: 0.7rem; margin-top: 4px; }
        a { text-decoration: none; color: inherit; display: block; height: 100%; }
        .filter-bar { margin-bottom: 20px; }
        button { background: #333; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; margin-right: 10px; }
        button:hover { background: var(--accent); }
    </style>
</head>
<body>
    <header>
        <div>
            <h1>Forensic Gallery</h1>
            <div class="stats">Recovered: """ + str(len(self.report_data)) + """ files | Generated: """ + datetime.now().strftime("%Y-%m-%d %H:%M") + """</div>
        </div>
    </header>

    <div class="grid">
"""
        
        for item in self.report_data:
            rel_path = item['relative_path']
            ext = item['extension']
            
            # Media element
            if ext in ['mp4', 'webm', 'mov']:
                media = f'<video controls preload="metadata"><source src="{rel_path}" type="video/{ext}"></video>'
            else:
                media = f'<img src="{rel_path}" loading="lazy" alt="Recovered">'
            
            # Card HTML
            html_content += f"""
        <div class="card">
            <div class="thumb">
                <a href="{rel_path}" target="_blank">{media}</a>
            </div>
            <div class="info">
                <div title="{item['recovered_name']}">{item['recovered_name']}</div>
                <span class="tag">{ext.upper()}</span> <span class="tag">{item['size_kb']} KB</span>
            </div>
        </div>"""

        html_content += """
    </div>
</body>
</html>"""
        
        try:
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            print(f"Gallery: {Fore.CYAN}{html_path}{Style.RESET_ALL}")
        except Exception as e:
            print(f"Gallery Error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Browser Forensics - Recover images/videos from browser cache')
    
    # Target
    parser.add_argument('--browser', choices=['chrome', 'edge', 'firefox', 'custom'], default='chrome', help='Target browser')
    parser.add_argument('--path', help='Custom path to cache directory')
    
    # Output & Structure
    parser.add_argument('--output', '-o', default='recovered_data', help='Output directory')
    parser.add_argument('--structure', choices=['flat', 'type', 'ext'], default='ext', 
                        help='Folder structure: "flat" (all in one), "type" (images/videos), "ext" (images/png)')
    
    # Flags
    parser.add_argument('--rename-hash', action='store_true', help='Rename files to SHA256 hash')
    parser.add_argument('--no-video', action='store_true', help='Skip videos')
    
    # Filters
    parser.add_argument('--min-size', type=int, default=1, help='Min size KB (default: 1)')
    parser.add_argument('--min-width', type=int, default=0, help='Min image width')
    parser.add_argument('--days', type=int, help='Last N days')
    
    # Misc
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging (disables progress bar usually)')
    
    args = parser.parse_args()

    recoverer = CacheRecoverer(
        browser=args.browser,
        custom_path=args.path,
        output_dir=args.output,
        min_size_kb=args.min_size,
        days=args.days,
        min_width=args.min_width,
        rename_hash=args.rename_hash,
        include_videos=not args.no_video,
        verbose=args.verbose,
        sort_by=args.structure
    )
    
    recoverer.process()

if __name__ == '__main__':
    main()
