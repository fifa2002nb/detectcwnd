# detectcwnd
This tool shows how to use syn，syn+ack and ack timestamps to calculate init_cwnd value in linux kernel.

## Running the example

The example requires a working Python and tcpdump development environment. The [Getting
Started](https://www.python.org/about/gettingstarted/) page describes how to install the
development environment.

Once you have Python and tcpdump up and running, you can download, build and run the example
using the following commands.

1. capture pcap file.
2. analyze pcap file.
```Bash
    #sh ./bin/cwind_analyzer.sh {pcap_file} {target_cdn_ip}
    $ sh ./bin/cwind_analyzer.sh ./data/5bde2082020b63fe2625903ff6760a42_1_0.pcap 211.151.109.110 
```
3. see the results in 'log' dir.
4. see [this page](http://www.apmbe.com/tcp%E5%8A%A0%E9%80%9F-%E5%88%9D%E5%A7%8B%E6%8B%A5%E5%A1%9E%E7%AA%97%E5%8F%A3%E8%B0%83%E6%95%B4/) for details of how to calculate init_cwnd in linux kernel.
