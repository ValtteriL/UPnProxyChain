# UPnProxyChain

A tool to create a SOCKS proxy server out of UPnProxy vulnerable device(s). Writeup [here](https://shufflingbytes.com/posts/upnproxychain-a-tool-to-exploit-devices-vulnerable-to-upnproxy/).

[![asciicast](https://asciinema.org/a/vPTh4dIcZRrnKyTbbFIGUnU5O.png)](https://asciinema.org/a/vPTh4dIcZRrnKyTbbFIGUnU5O)

## General information
UPnProxyChain is a tool to create a SOCKS proxy server out of UPnProxy vulnerable device(s). The proxy transparently forwards all connections through the vulnerable devices. Thus any tool supporting the SOCKS protocol can use the connection chain.

It takes a list of IP addresses to exploit as an argument. The addresses are used to create a chain through which connections will pass.

After the chain creation, its functionality is verified, and after that, a SOCKS proxy server is started.

On exit, UPnProxyChain will clean up the chain. That means it will delete all mappings it has created on the hosts to prevent them from staying there forever.

## Requirements
- Python3

## Usage

```
  _   _ ___      ___                   ___ _         _
 | | | | _ \_ _ | _ \_ _ _____ ___  _ / __| |_  __ _(_)_ _
 | |_| |  _/ ' \|  _/ '_/ _ \ \ / || | (__| ' \/ _` | | ' \
  \___/|_| |_||_|_| |_| \___/_\_\_, |\___|_||_\__,_|_|_||_|
                                 |__/

  Author: Valtteri Lehtinen <valtteri@shufflingbytes.com>
  Writeup: https://shufflingbytes.com/posts/upnproxychain-a-tool-to-exploit-devices-vulnerable-to-upnproxy/


usage: upnproxychain.py [-h] [-p PORT] [-l LISTENADDRESS] [-c] [-v] host [host ...]

A SOCKS proxy server that forwards traffic through a chain of exposed WANIP- or WANPPPConnection UPnP services

positional arguments:
  host                  hosts to use as proxy chain links in order

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  port for SOCKS proxy to listen on
  -l LISTENADDRESS, --listenaddress LISTENADDRESS
                        address for SOCKS proxy to listen on
  -c, --check           only check for UPnProxy vulnerability
  -v, --verbose         increase output verbosity
```

### Proxying
```
# start proxy
./upnproxychain.py <IP>

# use the proxy to curl example.com
curl socks5h://localhost:1080 http://example.com
```

### Check host for vulnerability
```
./upnproxychain.py -v -c <IP>
```

## How it works
The tool will send an SSDP discover message to the target host to discover its UPnP services. Target host with flawed UPnP implementation will respond with a URI pointing to a document describing its services.

The tool will then download the document, figure if the target is offering either WANPPPConnection or WANIPConnection service, and if so, start controlling the service to inject routes.

A device may not respond to UDP discover message even though it is exploitable. For those cases, UPnProxyChain will try to guess popular UPnP ports and URIs of service description documents and go from there.

Some devices are vulnerable but are not exploitable because they have a firewall blocking usage of any additional ports.

## Limitations
- SOCKS proxy supports only CONNECT command

