import glob
import os
import sys
import cap as mCAP
import feat as mFEAT
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich import print
from pathlib import Path

console = Console()

def show_menu():
    console.print(Panel.fit("[bold cyan]AL5084 - Disciplina de Desenvolvimento de Software PPGES Unipampa[/bold cyan]", border_style="cyan"))
    
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Available commands", style="cyan")
    table.add_column("Desciption")
    table.add_row("capture", "Traffic capture")
    table.add_row("features", "Automated extraction of flows/features from a capture")
    table.add_row("exit", "Exit")
    
    console.print(table)
    return Prompt.ask("Choose a command", choices=["capture", "features", "exit"])

def handle_capture():
    console.print(Panel.fit("[bold]Parameters for capture[/bold]", border_style="green"))

    c_outdir = Prompt.ask("Output directory of the .pcap file. Default is [cyan]captures/[/cyan]")
    if not c_outdir:
        console.print("[red]It is necessary to inform the output directory of the .pcap file![/red]")
        return

    iface = Prompt.ask("Network interface for capture (ex: eth0, enp0s3, etc).")
    if not iface:
        console.print("[red]It is necessary to inform the interface for capture![/red]")
        return
    
    duration = Prompt.ask("Time after which the capture will automatically end (in seconds). Default 10 seconds.", default="10")
    try:
        duration = int(duration)
    except ValueError:
        console.print("[red]Blank or invalid duration. Using the default of 10 seconds![/red]")
        duration = 10

    snaplen = Prompt.ask("SnapLen (in bytes). Default is 96.", default="96")
    try:
        snaplen = int(snaplen)
    except ValueError:
        console.print("[red]SnapLen blank or invalid. Using default 96 bytes![/red]")
        snaplen = 96
    
    console.print(f"\n[yellow]Running capture of interface '{iface}' for {duration} seconds in directory '{c_outdir}' with SnapLen of {snaplen} bytes.[/yellow]")
    mCAP.capture_pcap(Path(c_outdir), iface, duration, snaplen=snaplen)
    console.print("[green]Capture completed![/green]")


def handle_features():
    console.print(Panel.fit("[bold]Extract features from a PCAP[/bold]", border_style="blue"))
    
    o_dir = Path('captures/')
    captures = o_dir.glob('*.pcap')
    last_pcap = max(captures, key=os.path.getctime)

    pcap = Prompt.ask(f".pcap file for extraction. Last file [cyan]'{last_pcap}'[/cyan]")
    if not pcap:
        console.print("[red]Mandatory to inform the .pcap file![/red]")
        return

    f_outdir = Prompt.ask("Output directory for .csv files. Default is [cyan]features/[/cyan] ")
    if not f_outdir:
        console.print("[red]It is necessary to inform the output directory of the .csv files![/red]")
        return
    
    console.print(f"\n[yellow]Running feature/flow extraction from '{pcap}' in directory '{f_outdir}'[/yellow]")
    out_csvs = mFEAT.extract_features(Path(pcap), Path(f_outdir))
    console.print("\n".join(map(str, out_csvs)))
    console.print("[green]Extraction completed![/green]")

def main():
    while True:
        choice = show_menu()
        if choice == "capture":
            handle_capture()
        elif choice == "features":
            handle_features()
        elif choice == "exit":
            console.print("[cyan]Finishing...[/cyan]")
            break
        if not Confirm.ask("\nRun another command?"):
            console.print("[cyan]Finishing...[/cyan]")
            break

if __name__ == "__main__":
    main()
