# Network Watch Tower

*My first GoLang attempt*

I was in need of a small CLI utility to make an API request when a device connected to my WiFi network, but only after it had been missing for a certain period of time.

The idea is to have my smart lights automatically turn on when I arrive home, as the Location Services widget provided by IFTTT is extremely unreliable.

Go seemed like a good fit because I could make use of Goroutines.

This application uses the [GoPacket ](https://github.com/google/gopacket)library provided by Google to make ARP requests on a given interface to all valid IPv4 addresses to detect the prescence of a known set of MAC addresses. 

It keeps track of when the device was last seen, and if it has been missing for a given period of time and re-appears, it makes a `GET` request to a give URI.

### Usage

Compile `watch.go`, then execute as `root`:

`watch [-list] <interface> <config file>`

`-list` will produce a list of all available interfaces on your machine

`<interface>` the interface to scan

`<config file>` a JSON configuration file (see below)

### Config File

The config file is a simple JSON array specifying the following parameters:

```json
[
    {
        "HWAddress": "00:00:00:00:00:00",
        "Duration": "1h",
        "URL": "https://some.valid.call"
    }
]
```

You can specify as many devices you wish, each with their own configuration.

### Web Server

There is also a very rudimentary web server to keep track of the status of the application, you can access it on:

`http://<IP or Host>:8080`
