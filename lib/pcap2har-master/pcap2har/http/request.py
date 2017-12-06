import urlparse

# dpkt.http is buggy, so we use our modified replacement
from .. import dpkt_http_replacement as dpkt_http
import message as http


class Request(http.Message):
    '''
    HTTP request. Parses higher-level info out of dpkt.http.Request
    Members:
    * query: Query string name-value pairs. {string: [string]}
    * host: hostname of server.
    * fullurl: Full URL, with all components.
    * url: Full URL, but without fragments. (that's what HAR wants)
    '''

    def __init__(self, tcpdir, pointer):
        http.Message.__init__(self, tcpdir.fwd, pointer, dpkt_http.Request)
        # get query string. its the URL after the first '?'
        uri = urlparse.urlparse(self.msg.uri)
        self.host = self.msg.headers['host'] if 'host' in self.msg.headers else ''
        fullurl = urlparse.ParseResult('http', self.host, uri.path, uri.params, uri.query, uri.fragment)
        self.fullurl = fullurl.geturl()
        self.url, frag = urlparse.urldefrag(self.fullurl)
        self.query = urlparse.parse_qs(uri.query, keep_blank_values=True)
#add by xuxia
#        self.ts_end_real = tcpdir.rev.get_tcp_ts_by_index(1) if tcpdir.rev.get_tcp_ts_by_index(1) < tcpdir.rev.get_data_ts_by_index(0) else tcpdir.rev.get_data_ts_by_index(0)
        self.ts_end_real = tcpdir.rev.tcp_ts_by_ts_ge(self.ts_end) 
        tmp = tcpdir.rev.get_data_ts_by_index(0)
        if self.ts_end_real > tmp :
            self.ts_end_real = self.ts_end
        if self.ts_end_real is None :
            self.ts_end_real = self.ts_end
#print("%f %f %f" %(self.ts_start,self.ts_end,self.ts_end_real));

