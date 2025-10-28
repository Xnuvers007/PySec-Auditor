import os
from pyfiglet import Figlet
from rich.console import Console
from rich.live import Live
from rich.text import Text
from rich.panel import Panel
from .language import get_msg

console = Console()

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def start_spinner(text=None):
    text = text if text else get_msg("starting_audit")
    spinner = Live(f"[bold cyan]:hourglass: {text}[/bold cyan]", console=console, screen=False, refresh_per_second=10)
    spinner.start()
    return spinner

def display_ascii_art():
    f = Figlet(font='sblood')
    ascii_text = f.renderText('PySec.AUD')
    console.print(Panel(Text(ascii_text, style="bold red"), title=f"[bold white]{get_msg('title_main')}[/bold white]", border_style="magenta"))
