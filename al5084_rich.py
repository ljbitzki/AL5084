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
    table.add_column("Comandos disponíveis", style="cyan")
    table.add_column("Descrição")
    table.add_row("capture", "Captura/coleta de tráfego")
    table.add_row("features", "Extração automatizada de fluxos/features de uma coleta")
    table.add_row("exit", "Encerrar")
    
    console.print(table)
    return Prompt.ask("Escolha um comando", choices=["capture", "features", "exit"])

def handle_capture():
    console.print(Panel.fit("[bold]Parâmetros para captura[/bold]", border_style="green"))

    c_outdir = Prompt.ask("Diretório/ de saída do arquivo .pcap. Padrão é [cyan]captures/[/cyan]")
    if not c_outdir:
        console.print("[red]Necessário informar o diretório de saída do arquivo .pcap![/red]")
        return

    iface = Prompt.ask("Interface de rede para a captura/coleta (ex: eth0, enp0s3, etc).")
    if not iface:
        console.print("[red]Necessário informar a interface para a captura/coleta![/red]")
        return
    
    duration = Prompt.ask("Tempo em que a captura será encerrada automaticamente (em segundos). Padrão 10 segundos.", default="10")
    try:
        duration = int(duration)
    except ValueError:
        console.print("[red]Duração em branco ou inválido. Utilizando o padrão de 10 segundos![/red]")
        duration = 10

    snaplen = Prompt.ask("SnapLen (em bytes). Padrão 96.", default="96")
    try:
        snaplen = int(snaplen)
    except ValueError:
        console.print("[red]SnapLen em branco ou inválido. Utilizando o padrão de 96 bytes![/red]")
        snaplen = 96
    
    console.print(f"\n[yellow]Executando a captura da interface '{iface}' por {duration} segundos no diretório '{c_outdir}' com SnapLen de {snaplen} bytes.[/yellow]")
    mCAP.capture_pcap(Path(c_outdir), iface, duration, snaplen=snaplen)
    console.print("[green]Captura concluída![/green]")


def handle_features():
    console.print(Panel.fit("[bold]Extrair features de um PCAP[/bold]", border_style="blue"))
    
    o_dir = Path('captures/')
    captures = o_dir.glob('*.pcap')
    last_pcap = max(captures, key=os.path.getctime)

    pcap = Prompt.ask(f"Arquivo .pcap para extração. Último arquivo [cyan]'{last_pcap}'[/cyan]")
    if not pcap:
        console.print("[red]Obrigatório informar o arquivo .pcap![/red]")
        return

    f_outdir = Prompt.ask("Diretório de saída dos arquivos .csv. Padrão é [cyan]features/[/cyan] ")
    if not f_outdir:
        console.print("[red]Necessário informar o diretório de saída dos arquivos .csv!![/red]")
        return
    
    console.print(f"\n[yellow]Executando a extração de features/fluxos do '{pcap} no diretório '{f_outdir}'[/yellow]")
    out_csvs = mFEAT.extract_features(Path(pcap), Path(f_outdir))
    console.print("\n".join(map(str, out_csvs)))
    console.print("[green]✓ Extração concluída![/green]")

def main():
    while True:
        choice = show_menu()
        
        if choice == "capture":
            handle_capture()
        elif choice == "features":
            handle_features()
        elif choice == "exit":
            console.print("[cyan]Finalizando...[/cyan]")
            break
        
        if not Confirm.ask("\nExecutar outro comando?"):
            console.print("[cyan]Finalizando...[/cyan]")
            break

if __name__ == "__main__":
    main()
