import typer
import boto3
from rich.console import Console
from providers.aws.identity import get_identity

app = typer.Typer()
console = Console()

@app.command()
def scan(
    profile: str = typer.Option(None, help="AWS profile name"),
    region: str = typer.Option("us-east-1", help="AWS region")
):
    console.print("[bold green]cloudy[/bold green] starting scan...")

    session = boto3.Session(profile_name=profile, region_name=region)
    identity = get_identity(session)

    if 'error' in identity:
        console.print(f"[red][!] {identity['error']}[/red]")
        raise typer.Exit(1)

    console.print(f"\n[bold][*] identity[/bold]")
    console.print(f"    account:   {identity['account_id']}")
    console.print(f"    arn:       {identity['arn']}")
    console.print(f"    type:      {identity['type']}")

if __name__ == "__main__":
    app()
