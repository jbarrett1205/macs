import re



class IPv4Network(object):
    "representation of an IPv4 network"
    _ip_ok = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    _ip_net_ok = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(/\d{1,2})?$')
    
    def __init__(self, network):
        "initializer"
        
        if not self._ip_net_ok.match(network):
            raise ValueError("'%s' is not a valid IPv4 address or network"%network)
        
        x = network.split('/')
        if len(x) == 2:
            self._ip = x[0]
            self._mask = int(x[1])
        else:
            self._ip = x[0]
            self._mask = 32
        
        bin_ip = self._ip_to_bin(self._ip)
        self._bin_mask = self._mask_to_bin(self._mask)
        self._bin_network = bin_ip & self._bin_mask
        
        
    def in_network(self, ipaddr):
        "check if the specified IP is in the network"
        if not self._ip_ok.match(ipaddr):
            raise ValueError("'%s' is not a valid IPv4 address"%ipaddr)
            
        bin_ip = self._ip_to_bin(ipaddr)
        bin_net = bin_ip & self._bin_mask
        
        if bin_net == self._bin_network:
            return True
        
        return False
    
    def not_in_network(self, ipaddr):
        "opposite of in_network()"
        return not self.in_network(ipaddr)

    @staticmethod
    def _ip_to_bin( ipaddr ):
        """takes an IP address in the form X.X.X.X, where 0 <= X <= 255
        and converts it to a 32-bit unsigned integer
        
        """
        x = map(int,ipaddr.split('.'))
        if len(x) != 4:
            raise ValueError("IPv4 address does not have 4 parts -> '%s'"%ipaddr)
        
        for i in range(4):
            if x[i] < 0 or x[i] > 255:
                raise ValueError("IPv4 address segment %d falls outside allowed range of (0,255) -> '%s'"%(i+1,ipaddr))
        
        return x[0]*256*256*256 + x[1]*256*256 + x[2]*256 + x[3]
            
        
    @staticmethod
    def _mask_to_bin( mask ):
        """takes a netmask specifier and converts it to a 32-bit integer
        
        """
        if mask < 8 or mask > 32:
            raise ValueError("the network mask value must be 8 to 32")
        
        v = 0
        for i in xrange(32):
            v = v << 1
            if i < mask:
                v += 1
        
        return v
            
        
        
    
    
    
def compute_networks_and_masks( allowed_networks ):
    """
    
    returns a list of IPv4Network objects that can be used to compute if a given IPv4
    address resides within the network
    """
    
    if not isinstance(allowed_networks,(list,tuple)):
        raise TypeError("expected a list/tuple of IP addresses and/or networks")
    
    out = []
    for nw in allowed_networks:
        try:
            out.append(IPv4Network(nw))
        except Exception as e:
            raise ValueError("could not convert '%s' to a valid IPv4 network"%nw)
    
    return out
    
    
    