import os
import re
import json
import subprocess
import logging
from datetime import datetime
import requests
import yara
import configparser
import sys
from pathlib import Path
from tqdm import tqdm
from multiprocessing import Pool
from functools import partial
from colorama import Fore, Style, init
import argparse

init(autoreset=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("firmware_analyzer.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

def banner():
    logo = Fore.BLUE + r"""
___________.__                                                 _____                .__                           .___
\_   _____/|__|______  _______  _  _______ _______   ____     /  _  \   ____ _____  |  | ___.__.________ ____   __| _/
 |    __)  |  \_  __ \/     \ \/ \/ /\__  \\_  __ \_/ __ \   /  /_\  \ /    \\__  \ |  |<   |  |\___   // __ \ / __ | 
 |     \   |  ||  | \/  Y Y  \     /  / __ \|  | \/\  ___/  /    |    \   |  \/ __ \|  |_\___  | /    /\  ___// /_/ | 
 \___  /   |__||__|  |__|_|  /\/\_/  (____  /__|    \___  > \____|__  /___|  (____  /____/ ____|/_____ \\___  >____ | 
     \/                    \/             \/            \/          \/     \/     \/     \/           \/    \/     \/ 
"""
    print(logo)

class FirmwareAnalyzer:
    """ThemeHackers Firmware Analyzer for security analysis of firmware images."""
    
    def __init__(self, config_file="config.ini"):
        """Initialize with configuration file."""
        self.config = self._load_config(config_file)
        self.output_dir = self.config['output_dir']
        self.extract_dir = os.path.join(self.output_dir, "extracted")
        self.result_file = os.path.join(self.output_dir, "results.json")
        self.timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        self.extract_dir = os.path.join(self.output_dir, f"extracted-{self.timestamp}")
        self._version_cache = {}  

    def _load_config(self, config_file):
        """Load configuration from file or set defaults."""
        config = configparser.ConfigParser()
        default_config = {
            'output_dir': 'output_analyzed',
            'sensitive_patterns': r'password\s*=\s*["\']?.+["\']?,admin,token,secret,passwd',
            'bad_funcs': 'gets,strcpy,sprintf,system',
            'web_extensions': '.cgi,.php,.html',
            'shell_signatures': (
                r'base64_decode\(:high,eval\(:high,system\(:high,exec\(:medium,'
                r'passthru\(:medium,shell_exec\(:high,cmd\.exe:high,/bin/sh:high,'
                r'php\s+\$_POST\[.+\]:medium,\$_(GET|POST|REQUEST|COOKIE)\[:low'
            ),
            'max_file_size_mb': '10',
            'num_processes': '4'
        }
        config['DEFAULT'] = default_config
        if Path(config_file).exists():
            config.read(config_file)
        return config['DEFAULT']

    def _sanitize_path(self, path):
        """Sanitize file paths to prevent path traversal."""
        try:
            path = Path(path).resolve()
            if not path.exists():
                logger.error(f"Path does not exist: {path}")
                sys.exit(1)
            return str(path)
        except Exception as e:
            logger.error(f"Invalid path {path}: {e}")
            sys.exit(1)

    def extract_firmware(self, firmware_path):
        """Extract firmware using binwalk."""
        firmware_path = self._sanitize_path(firmware_path)
        try:
            os.makedirs(self.extract_dir, exist_ok=True)
            logger.info("Extracting firmware...")
            result = subprocess.run(
                ["binwalk", "--extract", "--directory", self.extract_dir, firmware_path],
                capture_output=True, text=True, timeout=300
            )
            if result.returncode != 0:
                logger.error(f"Binwalk extraction failed: {result.stderr}")
                sys.exit(1)
            logger.info("Firmware extracted successfully.")
        except Exception as e:
            logger.error(f"Failed to extract firmware: {e}")
            sys.exit(1)

    def _scan_file_for_sensitive_info(self, file_path, patterns):
        """Scan a single file for sensitive information."""
        results = []
        max_size = int(self.config['max_file_size_mb']) * 1024 * 1024
        if os.path.getsize(file_path) > max_size:
            logger.debug(f"Skipping large file: {file_path}")
            return results
        try:
            with open(file_path, 'r', errors='ignore') as f:
                lines = f.readlines()
                for i, line in enumerate(lines):
                    for p in patterns:
                        if re.search(p, line, re.IGNORECASE):
                            results.append({
                                'file': file_path,
                                'line': i + 1,
                                'match': line.strip()
                            })
        except Exception as e:
            logger.debug(f"Skipping file {file_path}: {e}")
        return results

    def find_sensitive_info(self, root_dir):
        """Scan for sensitive information in extracted files."""
        logger.info("Scanning for sensitive information...")
        patterns = self.config['sensitive_patterns'].split(',')
        results = []
        files = [os.path.join(root, f) for root, _, fs in os.walk(root_dir) for f in fs]
        
        if not files:
            logger.warning("No files found to scan for sensitive information.")
            return results

        with Pool(int(self.config['num_processes'])) as pool:
            func = partial(self._scan_file_for_sensitive_info, patterns=patterns)
            for result in tqdm(
                pool.imap_unordered(func, files),
                total=len(files),
                desc=f"{Fore.CYAN}Scanning Sensitive Info{Style.RESET_ALL}",
                unit="file",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                leave=True,
                colour="blue"
            ):
                results.extend(result)
        
        return results

    def _scan_binary_for_dangerous_funcs(self, file_path, bad_funcs):
        """Scan a single binary for dangerous functions."""
        findings = []
        max_size = int(self.config['max_file_size_mb']) * 1024 * 1024
        if os.path.getsize(file_path) > max_size:
            logger.debug(f"Skipping large file: {file_path}")
            return findings
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                for func in bad_funcs:
                    if func in data:
                        findings.append({
                            'file': file_path,
                            'dangerous_func': func.decode()
                        })
        except:
            pass
        return findings

    def scan_binaries_for_dangerous_funcs(self, root_dir):
        """Scan binaries for dangerous functions."""
        logger.info("Scanning binaries for dangerous functions...")
        bad_funcs = [b.encode() for b in self.config['bad_funcs'].split(',')]
        findings = []
        files = [os.path.join(root, f) for root, _, fs in os.walk(root_dir) for f in fs]
        
        if not files:
            logger.warning("No files found to scan for dangerous functions.")
            return findings

        with Pool(int(self.config['num_processes'])) as pool:
            func = partial(self._scan_binary_for_dangerous_funcs, bad_funcs=bad_funcs)
            for result in tqdm(
                pool.imap_unordered(func, files),
                total=len(files),
                desc=f"{Fore.CYAN}Scanning Binaries{Style.RESET_ALL}",
                unit="file",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                leave=True,
                colour="green"
            ):
                findings.extend(result)
        
        return findings

    def scan_web_scripts(self, root_dir):
        """Scan for web scripts (CGI, PHP, HTML)."""
        logger.info("Scanning for web interfaces...")
        web_extensions = tuple(self.config['web_extensions'].split(','))
        web_paths = [
            os.path.join(root, file)
            for root, _, files in os.walk(root_dir)
            for file in files
            if file.endswith(web_extensions)
        ]
        if not web_paths:
            logger.warning("No web scripts found.")
        return web_paths

    def _scan_file_for_web_shells(self, file_path, shell_signatures):
        """Scan a single file for web shell signatures."""
        matches = []
        if not file_path.endswith(('.php', '.cgi')):
            return matches
        try:
            with open(file_path, 'r', errors='ignore') as f:
                content = f.read()
                for sig, severity in shell_signatures:
                    if re.search(sig, content, re.IGNORECASE):
                        matches.append({
                            'file': file_path,
                            'signature': sig,
                            'severity': severity
                        })
                        break
        except:
            pass
        return matches

    def detect_web_shells(self, root_dir):
        """Detect potential web shells."""
        logger.info("Scanning for possible web shells...")
        shell_signatures = [
            (sig.split(':')[0], sig.split(':')[1])
            for sig in self.config['shell_signatures'].split(',')
        ]
        matches = []
        files = [
            os.path.join(root, f)
            for root, _, fs in os.walk(root_dir)
            for f in fs
            if f.endswith(('.php', '.cgi'))
        ]
        
        if not files:
            logger.warning("No PHP or CGI files found to scan for web shells.")
            return matches

        with Pool(int(self.config['num_processes'])) as pool:
            func = partial(self._scan_file_for_web_shells, shell_signatures=shell_signatures)
            for result in tqdm(
                pool.imap_unordered(func, files),
                total=len(files),
                desc=f"{Fore.CYAN}Scanning Web Shells{Style.RESET_ALL}",
                unit="file",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                leave=True,
                colour="red"
            ):
                matches.extend(result)
        
        return matches

    def _extract_version_from_binary(self, binary_path, args_list):
        """Extract version from a binary."""
        for arg in args_list:
            try:
                result = subprocess.run(
                    [binary_path, arg], capture_output=True, text=True, timeout=3
                )
                output = result.stdout + result.stderr
                ver = self._parse_version_from_text(output)
                if ver:
                    return ver
            except:
                pass
        
        try:
            with open(binary_path, 'rb') as f:
                data = f.read(4096)
                text = data.decode(errors='ignore')
                ver = self._parse_version_from_text(text)
                if ver:
                    return ver
        except:
            pass
        return None

    def _parse_version_from_text(self, text):
        """Parse version number from text."""
        patterns = [
            r"version\s*([\d\.]+)",
            r"v([\d\.]+)",
            r"busybox\s*v?([\d\.]+)",
            r"dropbear\s*v?([\d\.]+)",
            r"(\d+\.\d+\.\d+)"
        ]
        for p in patterns:
            m = re.search(p, text, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def detect_binary_versions(self, root_dir):
        """Detect versions of common binaries."""
        if self._version_cache:
            logger.debug("Using cached binary versions.")
            return self._version_cache

        logger.info("Detecting versions of common binaries...")
        binaries = {
            "busybox": None,
            "dropbear": None
        }
        version_results = {}
        
        for root, _, files in os.walk(root_dir):
            for file in files:
                path = os.path.join(root, file)
                fname = file.lower()
                try:
                    for binary in binaries:
                        if binary in fname and binaries[binary] is None:
                            version = self._extract_version_from_binary(
                                path, [f"--{opt}" for opt in ['help', 'version', 'v']]
                            )
                            if version:
                                binaries[binary] = version
                    if all(v is not None for v in binaries.values()):
                        break
                except:
                    continue
        
        for k, v in binaries.items():
            if v:
                version_results[k] = v
        
        self._version_cache = version_results
        return version_results

    def query_cve(self, product_name, version):
        """Query CVE database for vulnerabilities."""
        if not version or version.strip() == "...":
            logger.warning(f"Skipping CVE query for {product_name}: Invalid version '{version}'")
            return []
        
        url = f"https://cve.circl.lu/api/search/{product_name}/{version}"
        logger.info(f"Querying CVE database for {product_name} version {version}...")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            return response.json().get('results', [])
        except requests.RequestException as e:
            logger.warning(f"Failed to query CVE for {product_name}: {e}")
            return []

    def scan_cve_for_binaries(self, version_info=None):
        """Scan CVE for detected binary versions."""
        logger.info("Scanning CVE for detected binaries...")
        if version_info is None:
            version_info = self._version_cache
        return {binary: self.query_cve(binary, version) for binary, version in version_info.items()}

    def scan_with_yara(self, rules_dir, target_dir):
        """Scan files with YARA rules, handling invalid rules gracefully."""
        logger.info("Scanning with YARA rules...")
        matches = []
        
        try:
            rule_index = {
                os.path.splitext(f)[0]: os.path.join(r, f)
                for r, _, fs in os.walk(rules_dir)
                for f in fs if f.endswith(('.yar', '.yara'))
            }
            if not rule_index:
                logger.warning("No YARA rules found in the rules directory.")
                return []
            
            
            compiled_rules = []
            for rule_name, rule_path in rule_index.items():
                try:
                    rule = yara.compile(filepath=rule_path)
                    compiled_rules.append(rule)
                except yara.SyntaxError as e:
                    logger.error(f"YARA Syntax Error in {rule_path}: {e}")
                    continue
                except Exception as e:
                    logger.error(f"Failed to compile YARA rule {rule_path}: {e}")
                    continue
            
            if not compiled_rules:
                logger.error("No valid YARA rules compiled. Skipping YARA scan.")
                return []
            
            files = [os.path.join(root, f) for root, _, fs in os.walk(target_dir) for f in fs]
            if not files:
                logger.warning("No files found to scan with YARA rules.")
                return matches

            for file in tqdm(
                files,
                desc=f"{Fore.CYAN}Scanning YARA Rules{Style.RESET_ALL}",
                unit="file",
                bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                leave=True,
                colour="yellow"
            ):
                try:
                    for rule in compiled_rules:
                        matches_found = rule.match(file)
                        for match in matches_found:
                            matches.append({
                                "file": file,
                                "rule": match.rule,
                                "tags": match.tags,
                                "meta": match.meta
                            })
                except Exception as e:
                    logger.debug(f"Skipping file {file} during YARA scan: {e}")
                    continue
        except Exception as e:
            logger.error(f"Unexpected error during YARA scan: {e}")
            return []
        
        return matches

    def write_results(self, results):
        """Write analysis results to JSON file."""
        os.makedirs(self.output_dir, exist_ok=True)
        results_with_metadata = {
            "timestamp": self.timestamp,
            "tool": "ThemeHackers Firmware Analyzer",
            "yara_rules_credit": "https://github.com/Yara-Rules/rules",
            "analysis": results
        }
        try:
            with open(self.result_file, 'w') as f:
                json.dump(results_with_metadata, f, indent=4)
            logger.info(f"Report saved to: {self.result_file}")
        except Exception as e:
            logger.error(f"Failed to write results: {e}")
            sys.exit(1)

    def run(self, firmware_path, yara_rules_dir=None):
        """Run the full firmware analysis."""
        self.extract_firmware(firmware_path)
        
        subfolders = [f.path for f in os.scandir(self.extract_dir) if f.is_dir()]
        if not subfolders:
            logger.error("No extracted folder found!")
            sys.exit(1)
        full_extract_path = subfolders[0]
        
        version_info = self.detect_binary_versions(full_extract_path)
        
        results = {
            "credentials": self.find_sensitive_info(full_extract_path),
            "binary_risks": self.scan_binaries_for_dangerous_funcs(full_extract_path),
            "web_scripts": self.scan_web_scripts(full_extract_path),
            "possible_web_shells": self.detect_web_shells(full_extract_path),
            "detected_versions": version_info,
            "cve_results": self.scan_cve_for_binaries(version_info),
            "yara_matches": self.scan_with_yara(yara_rules_dir, full_extract_path) if yara_rules_dir else []
        }
        
        self.write_results(results)

def main():
    banner()    
    parser = argparse.ArgumentParser(
        description="ThemeHackers Firmware Analyzer - A tool for analyzing firmware images for security vulnerabilities. "
                    "YARA rules credit: https://github.com/Yara-Rules/rules",
        epilog="Developed by ThemeHackers"
    )
    parser.add_argument("firmware", help="Path to firmware .bin file")
    parser.add_argument("--yararules", help="Path to YARA rules directory", default=None)
    args = parser.parse_args()
    
    analyzer = FirmwareAnalyzer()
    analyzer.run(args.firmware, args.yararules)

if __name__ == "__main__":
    main()