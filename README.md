# detectcwnd
This tool shows how to use syn，syn+ack and ack timestamps to calculate init_cwnd value in linux kernel.

## Running the example

The example requires a working Python and tcpdump development environment. The [Getting
Started](https://www.python.org/about/gettingstarted/) page describes how to install the
development environment.

Once you have Python and tcpdump up and running, you can download, build and run the example
using the following commands.

1. capture pcap file:
2. analyze pcap file:

    #sh ./bin/cwind_analyzer.sh {pcap_file} {target_cdn_ip}
    $ sh ./bin/cwind_analyzer.sh ./data/5bde2082020b63fe2625903ff6760a42_1_0.pcap 211.151.109.110 
    
3. to see the results in 'log' dir.
