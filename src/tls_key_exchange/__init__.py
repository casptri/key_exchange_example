import click

@click.group()
def cli():
    pass

@cli.command()
def init():
    print("Hello from tls_key_exchange!")

