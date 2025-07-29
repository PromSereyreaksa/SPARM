#!/usr/bin/env python3

import os
import sys
import time
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
    """Display ASCII art banner"""
    art = f"""
╔═══════════════════════════════════════════════════════════════╗
║  ███████╗██████╗  █████╗ ██████╗ ███╗   ███╗                  ║
║  ██╔════╝██╔══██╗██╔══██╗██╔══██╗████╗ ████║                  ║
║  ███████╗██████╔╝███████║██████╔╝██╔████╔██║                  ║
║  ╚════██║██╔═══╝ ██╔══██║██╔══██╗██║╚██╔╝██║                  ║
║  ███████║██║     ██║  ██║██║  ██║██║ ╚═╝ ██║                  ║
║  ╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝                  ║
║                                                               ║
║        TVER EY KOR BAN OY TA COPPSARY                         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
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
    """Wait for user input to continue"""
    Confirm.ask("\n[bold cyan]Press Enter to continue[/bold cyan]", default=True, show_default=False)

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