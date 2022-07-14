from random import randint
import time
from rich import print
from rich.layout import Layout
from rich.panel import Panel
from rich.live import Live
from rich.console import Console


layout = Layout()
message = []
list = ["fsklfj", "fsfef"]
ip, port = "192.158.144.263", "25486"
lmessage = ""
for i in message:
    lmessage += i + "\n"
llist = ""
for i in list:
    llist = i + "[purple] - [white]" + llist

while True:
   
    xxx = randint(100, 999)    
    with Live(layout, refresh_per_second=60):
        layout = Layout()
        console = Console()
        layout.split_column(
            Layout(Panel("XXXX", title="tA1"), name="A1"),
            Layout(Panel(f"{lmessage}", title="[bold purple]Live Message", title_align="left", subtitle="[bold green]Write your message down here", subtitle_align="left", border_style="yellow"), name="A2"),
        )
        layout["A1"].split_column(
            Layout(Panel(f"\n[bold yellow]ANNC-CRYPTED-IRC\n[green]Server IP[white] = [magenta]{ip}[yellow]:[magenta]{port}", title="[bold yellow]\nANNC-CRYPTED-IRC", border_style="black"), name="A3"),
            Layout(Panel("XXXX", title="tA4"), name="A4")
        )
        layout["A4"].split_row(
            Layout(Panel(f"{llist}", title="[bold purple]Connected Clients", title_align="left", border_style="bold cyan"), name="A6"),
            Layout(Panel(f"[green]HASHE[white] = [green]{randint(848975316873513542135416876487864867687486,948975316873513542135416876487864867687486)}", title="[bold purple]Server Sercurity Check Var", title_align="left", border_style="bold cyan"), name="A7")
        )

    aaa = input(">:")
    message.append(aaa+"\n")
    lmessage = ""
    for i in message:
        lmessage = f"\n[blue][ {list[randint(0,len(list)-1)]} ] # [white]" + i + "\n" + lmessage

    time.sleep(0.1)
    list.append(str(xxx))
    llist = ""
    for i in list:
        llist = i + "[purple] - [white]" + llist
    print(layout)
