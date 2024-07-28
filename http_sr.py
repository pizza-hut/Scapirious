# 

```
from scapy.all import *

def establish_tcp_connection(ip_address):
    ip_packet = IP(dst=ip_address)
    tcp_packet = TCP(dport=80, flags="S")
    send(ip_packet / tcp_packet, verbose=0)
    response = sr1(ip_packet / TCP(dport=80), verbose=0)
    tcp_packet.flags = "A"
    send(ip_packet / tcp_packet, verbose=0)
    return tcp_packet

def send_http_request(tcp_packet, ip_address):
    http_packet = Raw(b"GET / HTTP/1.1\r\nHost: (link unavailable)\r\n\r\n")
    send(IP(dst=ip_address) / tcp_packet / http_packet, verbose=0)

def receive_http_response(ip_address):
    packets = []
    while True:
        response = sr1(IP(dst=ip_address) / TCP(dport=80), verbose=0)
        packets.append(response)
        if "0\r\n\r\n" in response[Raw].load.decode():  # Check for the final chunk
            break
    return packets

def assemble_chunks(packets):
    response_body = ""
    for packet in packets:
        chunk_size = packet[Raw].load.decode().split("\r\n")[0]
        if chunk_size == "0":  # Final chunk
            break
        chunk_data = packet[Raw].load.decode().split("\r\n\r\n")[1]
        response_body += chunk_data
    return response_body

def check_http_status(response_body):
    if "200 OK" in response_body:
        print("HTTP Status: 200 OK")
    elif "404 Not Found" in response_body:
        print("HTTP Status: 404 Not Found")
    else:
        print("HTTP Status: Unknown")

def main():
    ip_address = "192.168.1.100"
    tcp_packet = establish_tcp_connection(ip_address)
    send_http_request(tcp_packet, ip_address)
    packets = receive_http_response(ip_address)
    response_body = assemble_chunks(packets)
    check_http_status(response_body)
    print(response_body)

if __name__ == "__main__":
    main()
```

This updated code removes the menu and directly performs the actions: establishing a TCP connection, sending an HTTP request, receiving the HTTP response, assembling the chunks, checking the HTTP status, and printing the response body.
