# Captive-Portal Solution for NFTables

This is a captive-portal service that runs behind a webserver. It asks for a password via POST request and will then extend a named set in nftables with the IP address of the requester. It supports IPv4 and IPv6, and would be extensible to run on iptables as well. 

## The Server
The captive-portal-server listens for HTTP requests. It is not able to serve static content, all it understands is listening for a single URL where it requests a POST request with one parameter: The parameter is 'password'. It will then compare this password against a configurable salted password hash. If the password matches the hash, the webserver-part will send an HTTP redirect to the client with a configurable URL. If the password does not match, it will also redirect to another configurable URL. 

The Server also listens on another port for GRPC. This is where the clients will connect to (one server can have an arbitrary number of clients). The clients will receive push notifications of new additions to the whitelist.

The server does not persist the whitelist data. This does not matter too much though, because the way the client persists to nftables survives client and server restarts.

## The Client
The captive-portal-client is a binary that connects to the captive-portal-server, receives push notifications about new whitelisted elements and will then run system commands to extend a named set (actually it's two named sets, one for IPv4 and one for IPv6) with corresponding timeouts. 

## Setup

### NGINX
Here is how I proxy requests from NGINX:

```
location /login {
  proxy_set_header X-Real-IP $remote_addr;
  proxy_pass http://captive-portal-server:8080/login;
}

```
The remaining setup on nginx is just serving static webpages on an encrypted webpage, this also includes the POST request. My static HTML looks like this:
```
<form action="/login" method="post">
  <input name="password" type="password" placeholder="Open the Sesame!">
  <input type="submit" value="Go!">
</form>
```

### Captive-Portal-Server
My server is started via systemd. You could also start your server in a Docker container.
This is my /etc/systemd/system/captive-portal-server.service:

```
[Unit]
Description=Captive portal grpc server
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/captive_portal_server --password_hash='$2a$14$.agEoHrc9zLMLlfBJy9LquGRhYcPfnV0sCnq6OLWN1uafbLU8IIOm' --redirect_success_url=https://my.webpage.com/hello/success --redirect_failure_url=https://my.webpage.com/hello/failed --use_http_header_ip=X-Real-IP
User=nobody

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

The hash `$2a$14$.agEoHrc9zLMLlfBJy9LquGRhYcPfnV0sCnq6OLWN1uafbLU8IIOm` corresponds to the plain-text password 'test'. Please don't use it. If you log into the captive portal server with a wrong password, it will log the salted hash. You could use that to create the hash for your new password.

You also see the server has a couple of flags. Many of them should be self-explaining. If you don't use `--use_http_header_ip`, it will default to the source IP of the caller, meaning you must not run behind a proxy in that case. Be aware that the server was not security-hardened and this might be a bad idea, but then the HTTP handler is trivial, and you can audit yourself if you want to. 

Be aware that the server listens on two ports. One of them is for HTTP, the other one for GRPC. It defaults to 8080 for HTTP, and 8081 for GRPC.

### Captive-Portal-Client
The client is simple to set up. Same goes as above, I run it on my firewalls with systemd. As the server allows any amount of clients to connect, you can have one captive portal for more than one firewall, meaning one portal can open many paths.

Systemd-File:

```
[Unit]
Description=Captive portal client
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/captive_portal_client --server_address=service.wogri.at:8081
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

The client allows you to configure the `nft_ipv4_set_name`, `nft_ipv6_set_name`, the path to the nft executable and it also needs the `nft_table_name`. Also if you're not done setting up your nftables, you could tell it to `--firewall_mode=dummy`, then it will only log its actions.

The client needs to run on the firewall that runs nftables, and it needs to run as root (server can run as an arbitrary user) to be able to run the nft commands.


### Installing dependencies and building the binary
You will need grpc to change the protos of this binary. You can find the instructions how to download and build grpc here: https://grpc.io/docs/quickstart/go.html

Beyond that the bcrypt library will also be needed. 
TL;DR instructions how to install the dependencies without reading the linked grpc quickstart guide above: 

Visit https://github.com/google/protobuf/releases and download pre-compiled binaries for your platform(protoc-<version>-<platform>.zip). 

* Unzip this file.
* Update the environment variable PATH to include the path to the protoc binary file.

Install the required go libraries:

```
$ go mod tidy
```

Building the binary should then be easy:

```
$ make
```

### NFTables

All the captive-portal-client is interested in are named sets, one for IPv4 and one for IPv6. It does not care about any actual firewall rules. Also if you don't have IPv6 in your nftables setup your client will still work.
Here is my relevant nft setup in /etc/nftables.conf, the `trusted_set` is the the named set that will be populated by the captive-portal-client here:

```
flush ruleset

table inet filter {
  set trusted_set { type ipv4_addr; flags timeout;}
  set trusted6_set { type ipv6_addr; flags timeout;}
  chain forward {
    type filter hook forward priority 0;

    ct state {established,related} counter accept
    ct state invalid counter log drop

    # I use fwmarks to mark packets as trusted, gives me an advantage to not differentiate between ipv4 and ipv6.
    ip saddr @trusted_set mark set 10
    ip6 saddr @trusted6_set mark set 10

    ip6 daddr $filer_6 jump to_filer
  }

  chain to_filer {
    # allow ssh and mosh traffic
    meta mark 10 tcp dport { ssh } counter accept
    meta mark 10 udp dport { 60000-61000 } counter accept
  }
}
```

## Security
Neither the HTTP Server nor the GRPC server listen on TLS ports. If you have to deploy in an untrusted environment, this is risky, and you should patch the code to enable TLS/SSL and send the patch to me. The fact that the captive-portal-client connects without encryption to the server is less worrysome, as whitelisted IPs are - in most cases - not very sensitive information. The password itself should be protected while it traverses your system during the POST request.
