#!/usr/bin/env python3

import os
import sys
import time
import logging
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print as rprint

console = Console()

def clear():
    """Clear terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def ascii_art(text):
    """Display compact ASCII art banner"""
    art = """
┌─────────────────────────────────────────────────────────┐
│  ███████╗██████╗  █████╗ ██████╗ ███╗   ███╗             │
│  ██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║             │
│  ███████╗██████╔╝███████║██████╔╝██╔████╔██║             │
│  ╚════██║██╔═══╝ ██╔══██║██╔══██╗██║╚██╔╝██║             │
│  ███████║██║     ██║  ██║██║  ██║██║ ╚═╝ ██║             │
│  ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝             │
│                                                         │
│     [bold red]S[/bold red]ecurity [bold red]P[/bold red]enetration & [bold red]A[/bold red]ttack [bold red]R[/bold red]esearch [bold red]M[/bold red]ultitool     │
│                    [dim]v2.0.0 - Educational Use Only[/dim]           │
└─────────────────────────────────────────────────────────┘
    """
    console.print(art, style="bold cyan")

def Title(title):
    """Display formatted title"""
    console.print(Panel(title, style="bold green", padding=(1, 2)))

def banner(text):
    """Display banner with text"""
    console.print(Panel(f"[bold cyan]{text}[/bold cyan]", padding=(1, 2)))

def Success(message):
    """Display success message"""
    console.print(f"[bold green]✓[/bold green] {message}")

def Warning(message):
    """Display warning message"""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")

def ErrorModule(error):
    """Display error message and exit"""
    console.print(f"[bold red]✗ Error:[/bold red] {error}")
    sys.exit(1)

def info(message):
    """Display info message"""
    console.print(f"[bold blue]ℹ[/bold blue] {message}")

def Continue():
    """Wait for user input to continue without clearing output"""
    console.print("\n[bold cyan]Press Enter to continue (output will be preserved)[/bold cyan]")
    input()  # Use input() instead of Confirm.ask to preserve output

def get_user_input(prompt_text, choices=None):
    """Get user input with validation"""
    if choices:
        return Prompt.ask(prompt_text, choices=choices)
    return Prompt.ask(prompt_text)

def display_tools_table(category, tools):
    """Display tools in a formatted table"""
    table = Table(title=f"{category} Tools")
    table.add_column("ID", style="cyan", width=6)
    table.add_column("Tool", style="green", width=20)
    table.add_column("Description", style="white")
    
    for i, (tool_name, description) in enumerate(tools.items(), 1):
        table.add_row(str(i), tool_name, description)
    
    console.print(table)

def show_next_steps(current_phase, suggestions):
    """Display next step suggestions"""
    console.print("\n[bold cyan]🎯 Suggested Next Steps:[/bold cyan]")
    for i, suggestion in enumerate(suggestions, 1):
        console.print(f"  {i}. {suggestion}")
    console.print()

def compact_menu_header():
    """Display compact menu header with system info"""
    import platform
    import datetime
    
    current_time = datetime.datetime.now().strftime("%H:%M:%S")
    
    header = f"""
[bold cyan]┌─[/bold cyan] [bold white]SPARM v2.0[/bold white] [bold cyan]─[/bold cyan] [bold green]{platform.node()}[/bold green] [bold cyan]─[/bold cyan] [bold yellow]{current_time}[/bold yellow] [bold cyan]─┐[/bold cyan]
[bold cyan]│[/bold cyan] [bold red]Security Penetration & Attack Research Multitool[/bold red] [bold cyan]│[/bold cyan]
[bold cyan]└─────────────────────────────────────────────────────┘[/bold cyan]
    """
    console.print(header)

def display_compact_menu_item(number, icon, name, description, color="cyan"):
    """Display a compact menu item"""
    console.print(f"[bold {color}]┌─[[/bold {color}][bold white]{number:02d}[/bold white][bold {color}]][/bold {color}] {icon} [bold white]{name}[/bold white]")
    console.print(f"[bold {color}]└──[/bold {color}] [dim]{description}[/dim]")

def display_three_row_menu(menu_items):
    """Display menu items in three rows"""
    rows = [[], [], []]
    
    # Distribute items across three rows
    for i, item in enumerate(menu_items):
        rows[i % 3].append(item)
    
    # Display each row
    for row_index, row in enumerate(rows):
        if row:  # Only display if row has items
            console.print(f"\n[bold cyan]Row {row_index + 1}:[/bold cyan]")
            for choice, icon, name, description, color in row:
                console.print(f"  [bold {color}][{choice}][/bold {color}] {icon} [bold white]{name}[/bold white] - [dim]{description}[/dim]")

def status_line(level, status):
    """Display compact status line"""
    level_colors = {
        "beginner": "green",
        "intermediate": "yellow", 
        "advanced": "red"
    }
    color = level_colors.get(level, "cyan")
    console.print(f"[bold {color}]▸[/bold {color}] Level: [bold white]{level.title()}[/bold white] [bold cyan]|[/bold cyan] Status: [bold green]{status}[/bold green]")

def separator():
    """Display a visual separator"""
    console.print("[dim cyan]" + "─" * 60 + "[/dim cyan]")

def check_tool_installed(tool_name):
    """Check if a tool is installed and accessible"""
    import shutil
    return shutil.which(tool_name) is not None

def run_command_with_realtime_output(command, timeout=300, log_file=None):
    """Run command with real-time output streaming"""
    import subprocess
    import shlex
    
    if log_file:
        log_command_start(log_file, "realtime_command", str(command))
    
    console.print(f"\n[bold green]Executing: {command}[/bold green]")
    console.print("[dim]Real-time output (Press Ctrl+C to stop):[/dim]\n")
    
    try:
        # Use shell=True for complex commands with pipes and redirects
        if isinstance(command, str) and ('|' in command or '>' in command or '<' in command):
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
        else:
            # For simple commands, use shell=False for better security
            if isinstance(command, str):
                command = shlex.split(command)
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True
            )
        
        output_lines = []
        
        # Read output line by line
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                # Display real-time output
                clean_output = output.rstrip()
                safe_output = clean_output.replace('[', r'\[').replace(']', r'\]')
                console.print(safe_output)
                output_lines.append(clean_output)
                
                # Log to file
                if log_file:
                    log_output_line(log_file, clean_output)
        
        # Wait for process to complete
        return_code = process.wait()
        
        if log_file:
            log_command_end(log_file, "realtime_command", return_code)
        
        console.print(f"\n[bold {'green' if return_code == 0 else 'yellow'}]Command completed with exit code: {return_code}[/bold {'green' if return_code == 0 else 'yellow'}]")
        
        if log_file:
            Success(f"Session logged to: {log_file}")
        
        return return_code == 0, '\n'.join(output_lines), ""
        
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Command interrupted by user[/bold yellow]")
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            process.kill()
        
        if log_file:
            log_output_line(log_file, "Command interrupted by user")
        
        return False, "", "Interrupted"
        
    except subprocess.TimeoutExpired:
        console.print(f"\n[bold red]Command timed out after {timeout} seconds[/bold red]")
        if log_file:
            log_output_line(log_file, f"Command timed out after {timeout} seconds")
        return False, "", "Timeout"
        
    except Exception as e:
        console.print(f"\n[bold red]Error executing command: {e}[/bold red]")
        if log_file:
            log_output_line(log_file, f"Error: {e}")
        return False, "", str(e)

def safe_subprocess_run(command, timeout=300, show_output=True, log_file=None):
    """Safely run subprocess with proper error handling and logging"""
    import subprocess
    import shlex
    
    if log_file:
        log_command_start(log_file, "subprocess", str(command))
    
    try:
        # For complex commands with quotes, use shell=True
        if isinstance(command, str) and ('"' in command or "'" in command):
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True, 
                text=True, 
                timeout=timeout,
                check=False
            )
        else:
            # For simple commands, split and use shell=False
            if isinstance(command, str):
                command = shlex.split(command)
            
            result = subprocess.run(
                command, 
                capture_output=True, 
                text=True, 
                timeout=timeout,
                check=False
            )
        
        if show_output:
            if result.stdout.strip():
                console.print("\n[bold green]Results:[/bold green]")
                # Escape Rich markup in output to prevent parsing errors
                safe_stdout = result.stdout.replace('[', r'\[').replace(']', r'\]')
                console.print(safe_stdout)
                if log_file:
                    for line in result.stdout.strip().split('\n'):
                        log_output_line(log_file, line)
            else:
                console.print("\n[bold yellow]No output received from command[/bold yellow]")
                if log_file:
                    log_output_line(log_file, "No output received")
                
            if result.stderr.strip():
                # Escape Rich markup in error output too
                safe_stderr = result.stderr.replace('[', r'\[').replace(']', r'\]')
                Warning(f"Errors: {safe_stderr}")
                if log_file:
                    log_output_line(log_file, f"ERROR: {result.stderr}")
                
            # Show return code for debugging
            if result.returncode != 0:
                console.print(f"[bold red]Exit code: {result.returncode}[/bold red]")
            else:
                console.print(f"[bold green]Exit code: {result.returncode}[/bold green]")
            
            if log_file:
                log_command_end(log_file, "subprocess", result.returncode)
        
        return result.returncode == 0, result.stdout, result.stderr
        
    except subprocess.TimeoutExpired:
        Warning(f"Command timed out after {timeout} seconds")
        if log_file:
            log_output_line(log_file, f"Command timed out after {timeout} seconds")
        return False, "", "Timeout"
    except FileNotFoundError:
        Warning(f"Command not found: {command[0] if isinstance(command, list) and command else 'Unknown'}")
        if log_file:
            log_output_line(log_file, "Command not found")
        return False, "", "Command not found"
    except Exception as e:
        Warning(f"Error executing command: {e}")
        if log_file:
            log_output_line(log_file, f"Error: {e}")
        return False, "", str(e)

def scan_wordlist_directory(wordlist_type=None):
    """Scan wordlist directory and return available wordlists"""
    import glob
    
    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    wordlist_base = os.path.join(current_dir, "wordlists")
    
    if not os.path.exists(wordlist_base):
        return []
    
    wordlists = []
    
    if wordlist_type:
        # Look in specific subdirectory
        subdir = os.path.join(wordlist_base, wordlist_type)
        if os.path.exists(subdir):
            patterns = ["*.txt", "*.lst", "*.dic"]
            for pattern in patterns:
                wordlists.extend(glob.glob(os.path.join(subdir, "**", pattern), recursive=True))
    else:
        # Scan all wordlists
        patterns = ["*.txt", "*.lst", "*.dic"]
        for pattern in patterns:
            wordlists.extend(glob.glob(os.path.join(wordlist_base, "**", pattern), recursive=True))
    
    # Also check root wordlist directory
    patterns = ["*.txt", "*.lst", "*.dic"]
    for pattern in patterns:
        wordlists.extend(glob.glob(os.path.join(wordlist_base, pattern)))
    
    # Remove duplicates and sort
    wordlists = sorted(list(set(wordlists)))
    
    return wordlists

def select_wordlist_from_directory(wordlist_type=None, prompt_text=None):
    """Select wordlist from dedicated wordlist directory"""
    if not prompt_text:
        prompt_text = f"Select {wordlist_type or 'wordlist'}"
    
    available = scan_wordlist_directory(wordlist_type)
    
    if not available:
        Warning(f"No {wordlist_type or 'wordlists'} found in wordlists directory!")
        return None
    
    console.print(f"\n[bold cyan]Available {wordlist_type or 'wordlists'}:[/bold cyan]")
    
    # Group by directory for better organization
    grouped = {}
    for wordlist in available:
        rel_path = os.path.relpath(wordlist, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "wordlists"))
        dir_name = os.path.dirname(rel_path) if os.path.dirname(rel_path) != '.' else 'Root'
        
        if dir_name not in grouped:
            grouped[dir_name] = []
        grouped[dir_name].append((wordlist, os.path.basename(wordlist)))
    
    # Display grouped wordlists
    all_wordlists = []
    counter = 1
    
    for dir_name, wordlists in sorted(grouped.items()):
        if len(grouped) > 1:  # Only show directory names if there are multiple
            console.print(f"\n[bold yellow]{dir_name}:[/bold yellow]")
        
        for full_path, filename in sorted(wordlists):
            try:
                size = os.path.getsize(full_path)
                if size < 1024:
                    size_str = f"({size}B)"
                elif size < 1024*1024:
                    size_str = f"({size//1024}KB)"
                else:
                    size_str = f"({size//1024//1024}MB)"
            except:
                size_str = ""
            
            console.print(f"  [bold green]{counter:2d}.[/bold green] {filename} {size_str}")
            if len(grouped) > 1:  # Show full path if multiple directories
                console.print(f"      [dim]{os.path.relpath(full_path)}[/dim]")
            
            all_wordlists.append(full_path)
            counter += 1
    
    if not all_wordlists:
        Warning("No wordlists found!")
        return None
    
    while True:
        try:
            choice = int(get_user_input(f"{prompt_text} (1-{len(all_wordlists)})"))
            if 1 <= choice <= len(all_wordlists):
                selected = all_wordlists[choice - 1]
                Success(f"Selected: {os.path.basename(selected)}")
                return selected
            else:
                Warning(f"Please enter a number between 1 and {len(all_wordlists)}")
        except ValueError:
            Warning("Please enter a valid number")
        except KeyboardInterrupt:
            return None

def preserve_output_on_exit():
    """Prevent output clearing when exiting tools"""
    # This function can be called to ensure output persists
    # For now, we'll just add a pause to let users read output
    console.print("\n[dim]Output preserved. Press Enter to continue...[/dim]")
    input()

def validate_ip(ip_address):
    """Validate IP address format"""
    import ipaddress
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def validate_domain(domain):
    """Validate domain name format"""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, domain) is not None

def get_target_input(prompt="Enter target", allow_ip=True, allow_domain=True):
    """Get and validate target input (IP or domain)"""
    while True:
        target = get_user_input(prompt)
        
        if allow_ip and validate_ip(target):
            return target
        elif allow_domain and validate_domain(target):
            return target
        else:
            valid_types = []
            if allow_ip:
                valid_types.append("IP address")
            if allow_domain:
                valid_types.append("domain name")
            Warning(f"Invalid target. Please enter a valid {' or '.join(valid_types)}")

def format_command_output(command, success, stdout, stderr):
    """Format command output consistently"""
    console.print(f"\n[bold yellow]Command:[/bold yellow] {' '.join(command) if isinstance(command, list) else command}")
    
    if success:
        console.print("[bold green]✓ Command executed successfully[/bold green]")
        if stdout:
            console.print("\n[bold green]Output:[/bold green]")
            console.print(stdout)
    else:
        console.print("[bold red]✗ Command failed[/bold red]")
        if stderr:
            console.print(f"\n[bold red]Error:[/bold red] {stderr}")

def get_available_wordlists(wordlist_type):
    """Get list of available wordlists of specified type"""
    from .config import WORDLISTS
    import os
    
    if wordlist_type not in WORDLISTS:
        return []
    
    available = []
    for wordlist in WORDLISTS[wordlist_type]:
        if os.path.exists(wordlist):
            available.append(wordlist)
    
    return available

def select_wordlist(wordlist_type, prompt_text=None):
    """Interactive wordlist selection"""
    if not prompt_text:
        prompt_text = f"Select {wordlist_type} wordlist"
    
    available = get_available_wordlists(wordlist_type)
    
    if not available:
        Warning(f"No {wordlist_type} wordlists found!")
        return None
    
    console.print(f"\n[bold cyan]Available {wordlist_type} wordlists:[/bold cyan]")
    for i, wordlist in enumerate(available, 1):
        # Show just filename and size if possible
        filename = os.path.basename(wordlist)
        try:
            size = os.path.getsize(wordlist)
            size_str = f"({size//1024}KB)" if size < 1024*1024 else f"({size//1024//1024}MB)"
        except:
            size_str = ""
        console.print(f"  [bold green]{i}.[/bold green] {filename} {size_str}")
        console.print(f"      [dim]{wordlist}[/dim]")
    
    while True:
        try:
            choice = int(get_user_input(f"{prompt_text} (1-{len(available)})"))
            if 1 <= choice <= len(available):
                selected = available[choice - 1]
                Success(f"Selected: {os.path.basename(selected)}")
                return selected
            else:
                Warning(f"Please enter a number between 1 and {len(available)}")
        except ValueError:
            Warning("Please enter a valid number")

def select_seclist_wordlist(wordlist_type):
    """Select wordlist from SecLists collection with enhanced options"""
    # Get the base directory dynamically
    import os
    current_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    seclist_base = os.path.join(current_dir, "SecLists-master")
    
    if wordlist_type == "passwords":
        seclist_paths = {
            "Common Credentials": {
                "10M Top 1M": f"{seclist_base}/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt",
                "10M Top 100K": f"{seclist_base}/Passwords/Common-Credentials/10-million-password-list-top-100000.txt",
                "10M Top 10K": f"{seclist_base}/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
                "Best 1050": f"{seclist_base}/Passwords/Common-Credentials/best1050.txt",
                "DarkWeb 2017 Top 1000": f"{seclist_base}/Passwords/Common-Credentials/darkweb2017-top1000.txt",
                "Xato Net 10M": f"{seclist_base}/Passwords/Common-Credentials/xato-net-10-million-passwords-1000000.txt"
            },
            "Leaked Databases": {
                "RockYou": f"{seclist_base}/Passwords/Leaked-Databases/rockyou.txt.tar.gz",
                "Adobe Top 100": f"{seclist_base}/Passwords/Leaked-Databases/adobe100.txt",
                "MySpace": f"{seclist_base}/Passwords/Leaked-Databases/myspace.txt"
            },
            "Default Credentials": {
                "Default Passwords": f"{seclist_base}/Passwords/Default-Credentials/default-passwords.txt",
                "CIRT Collection": f"{seclist_base}/Passwords/Default-Credentials/cirt-net_collection.txt"
            }
        }
    elif wordlist_type == "usernames":
        seclist_paths = {
            "Common Names": {
                "Names": f"{seclist_base}/Usernames/Names/names.txt",
                "Top Usernames Short": f"{seclist_base}/Usernames/top-usernames-shortlist.txt",
                "Xato Net 10M": f"{seclist_base}/Usernames/xato-net-10-million-usernames.txt"
            },
            "Default Users": {
                "CIRT Default Users": f"{seclist_base}/Usernames/cirt-default-usernames.txt"
            }
        }
    else:
        Warning(f"Unsupported wordlist type: {wordlist_type}")
        return None
    
    console.print(f"\n[bold cyan]SecLists {wordlist_type.title()} Categories:[/bold cyan]")
    
    categories = list(seclist_paths.keys())
    for i, category in enumerate(categories, 1):
        console.print(f"  [bold green]{i}.[/bold green] {category}")
    
    try:
        cat_choice = int(get_user_input(f"Choose category (1-{len(categories)})"))
        if not 1 <= cat_choice <= len(categories):
            Warning("Invalid category selection")
            return None
        
        selected_category = categories[cat_choice - 1]
        wordlists = seclist_paths[selected_category]
        
        console.print(f"\n[bold cyan]{selected_category} Wordlists:[/bold cyan]")
        wordlist_items = list(wordlists.items())
        
        for i, (name, path) in enumerate(wordlist_items, 1):
            # Check if file exists and show size
            if os.path.exists(path):
                try:
                    size = os.path.getsize(path)
                    size_str = f"({size//1024}KB)" if size < 1024*1024 else f"({size//1024//1024}MB)"
                    status = "[bold green]✓[/bold green]"
                except:
                    size_str = ""
                    status = "[bold green]✓[/bold green]"
            else:
                size_str = "[bold red](Not Found)[/bold red]"
                status = "[bold red]✗[/bold red]"
            
            console.print(f"  {status} [bold green]{i}.[/bold green] {name} {size_str}")
        
        wordlist_choice = int(get_user_input(f"Choose wordlist (1-{len(wordlist_items)})"))
        if not 1 <= wordlist_choice <= len(wordlist_items):
            Warning("Invalid wordlist selection")
            return None
        
        selected_name, selected_path = wordlist_items[wordlist_choice - 1]
        
        if not os.path.exists(selected_path):
            Warning(f"Wordlist not found: {selected_path}")
            return None
        
        Success(f"Selected: {selected_name}")
        return selected_path
        
    except ValueError:
        Warning("Please enter a valid number")
        return None
    except Exception as e:
        Warning(f"Error selecting wordlist: {e}")
        return None

def setup_session_logging(tool_name):
    """Setup organized logging for tool session with numbered files"""
    # Create main logs directory
    base_log_dir = "/home/s001kaliv1/Desktop/SPARM/logs"
    os.makedirs(base_log_dir, exist_ok=True)
    
    # Create tool-specific directory
    tool_log_dir = os.path.join(base_log_dir, tool_name)
    os.makedirs(tool_log_dir, exist_ok=True)
    
    # Find next available number
    existing_logs = [f for f in os.listdir(tool_log_dir) if f.startswith(f"{tool_name}_") and f.endswith(".log")]
    
    # Extract numbers from existing logs
    numbers = []
    for log_file in existing_logs:
        try:
            # Extract number from filename like "hydra_1_log_timestamp.log"
            # Split filename and look for pattern: tool_NUMBER_log_timestamp
            parts = log_file.replace('.log', '').split('_')
            for i, part in enumerate(parts):
                if part.isdigit() and i > 0:  # First digit after tool name
                    if i + 1 < len(parts) and parts[i + 1] == 'log':
                        numbers.append(int(part))
                        break
        except (ValueError, IndexError):
            continue
    
    # Get next number
    next_number = max(numbers) + 1 if numbers else 1
    
    # Create filename with number
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(tool_log_dir, f"{tool_name}_{next_number}_log_{timestamp}.log")
    
    return log_file

def log_command_start(log_file, tool_name, command):
    """Log command start with enhanced header"""
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*70}\n")
        f.write(f"SPARM SESSION LOG - {tool_name.upper()}\n")
        f.write(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Log File: {os.path.basename(log_file)}\n")
        f.write(f"Command: {command}\n")
        f.write(f"{'='*70}\n\n")

def log_output_line(log_file, line):
    """Log a single output line"""
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {line}\n")

def log_command_end(log_file, tool_name, return_code):
    """Log command completion with summary"""
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"\n{'='*70}\n")
        f.write(f"SESSION COMPLETED - {tool_name.upper()}\n")
        f.write(f"Ended: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Exit code: {return_code}\n")
        f.write(f"Log File: {os.path.basename(log_file)}\n")
        f.write(f"{'='*70}\n")
        
def get_session_summary(log_file):
    """Get summary of recent sessions for a tool"""
    tool_name = os.path.basename(os.path.dirname(log_file))
    tool_log_dir = os.path.dirname(log_file)
    
    if not os.path.exists(tool_log_dir):
        return f"No previous sessions found for {tool_name}"
    
    # Get all log files for this tool
    log_files = [f for f in os.listdir(tool_log_dir) if f.endswith('.log')]
    log_files.sort(key=lambda x: os.path.getctime(os.path.join(tool_log_dir, x)), reverse=True)
    
    summary = f"\n📊 Recent {tool_name.upper()} Sessions:\n"
    summary += "=" * 40 + "\n"
    
    for i, log_file_name in enumerate(log_files[:5], 1):
        full_path = os.path.join(tool_log_dir, log_file_name)
        try:
            # Get file creation time
            created = datetime.fromtimestamp(os.path.getctime(full_path))
            size = os.path.getsize(full_path)
            
            # Extract session number from filename
            parts = log_file_name.replace('.log', '').split('_')
            session_num = "?"
            for j, part in enumerate(parts):
                if part.isdigit() and j > 0:
                    session_num = part
                    break
            
            summary += f"{i:2d}. {log_file_name}\n"
            summary += f"    Session #{session_num} | {created.strftime('%Y-%m-%d %H:%M')} | {size//1024}KB\n"
            
        except Exception as e:
            summary += f"{i:2d}. {log_file_name} (error reading details)\n"
    
    if len(log_files) > 5:
        summary += f"\n... and {len(log_files) - 5} more sessions\n"
    
    summary += f"\nTotal Sessions: {len(log_files)}\n"
    summary += "=" * 40 + "\n"
    
    return summary

def show_session_summary(tool_name):
    """Show summary of recent sessions for a tool"""
    base_log_dir = "/home/s001kaliv1/Desktop/SPARM/logs"
    tool_log_dir = os.path.join(base_log_dir, tool_name)
    
    if not os.path.exists(tool_log_dir):
        console.print(f"[yellow]No previous sessions found for {tool_name}[/yellow]")
        return
    
    # Get all log files for this tool
    log_files = [f for f in os.listdir(tool_log_dir) if f.endswith('.log')]
    
    if not log_files:
        console.print(f"[yellow]No log files found for {tool_name}[/yellow]")
        return
    
    log_files.sort(key=lambda x: os.path.getctime(os.path.join(tool_log_dir, x)), reverse=True)
    
    console.print(f"\n[bold cyan]📊 Recent {tool_name.upper()} Sessions:[/bold cyan]")
    console.print("=" * 50)
    
    for i, log_file_name in enumerate(log_files[:10], 1):
        full_path = os.path.join(tool_log_dir, log_file_name)
        try:
            # Get file creation time
            created = datetime.fromtimestamp(os.path.getctime(full_path))
            size = os.path.getsize(full_path)
            
            # Extract session number from filename
            parts = log_file_name.replace('.log', '').split('_')
            session_num = "?"
            for j, part in enumerate(parts):
                if part.isdigit() and j > 0:
                    session_num = part
                    break
            
            size_str = f"{size//1024}KB" if size < 1024*1024 else f"{size//1024//1024}MB"
            
            console.print(f"[bold green]{i:2d}.[/bold green] {log_file_name}")
            console.print(f"    [dim]Session #{session_num} | {created.strftime('%Y-%m-%d %H:%M')} | {size_str}[/dim]")
            
        except Exception as e:
            console.print(f"[bold green]{i:2d}.[/bold green] {log_file_name} [red](error reading details)[/red]")
    
    if len(log_files) > 10:
        console.print(f"\n[dim]... and {len(log_files) - 10} more sessions[/dim]")
    
    console.print(f"\n[bold yellow]Total Sessions: {len(log_files)}[/bold yellow]")
    console.print(f"[bold yellow]Log Directory: {tool_log_dir}[/bold yellow]")
    console.print("=" * 50)