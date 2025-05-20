from pathlib import Path
import aiohttp
import ssl
import asyncio

CA_CERTFILE     = "app/upload/ca.crt"
CLIENT_CERTFILE = "app/upload/client.crt"
CLIENT_KEYFILE  = "app/tls/client.key"

client_cert = (CLIENT_CERTFILE, CLIENT_KEYFILE)

dl_file = "README.md"
base_url = "https://localhost:8443/"
file_url = base_url + dl_file

dl_path = Path() / "download"
dl_path.mkdir(parents=True, exist_ok=True)

ssl_context = ssl.create_default_context(cafile=CA_CERTFILE)
ssl_context.check_hostname = False
#ssl_context.verify_mode = ssl.CERT_NONE
ssl_context.load_cert_chain(certfile=CLIENT_CERTFILE, keyfile=CLIENT_KEYFILE)

async def download(url, ssl):
    async with aiohttp.ClientSession() as session:
        async with session.get(url, ssl=ssl) as response:
            if response.status == 200:
                with (dl_path / dl_file).open('wb') as file:
                    while True:
                        chunk = await response.content.read(1024)
                        if not chunk:
                            break
                        file.write(chunk)


asyncio.run(download(file_url, ssl_context))
