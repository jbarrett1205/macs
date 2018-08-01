import re, socket
from functools import wraps
from django.core.exceptions import PermissionDenied
from . import settings

# allowed networks
_ALLOWED_NETWORKS = []

def macs_check_restricted_request(request):
    "check that the request should be allowed"
    try:
        remote_ip = request.META['REMOTE_ADDR']
        for nw in _ALLOWED_NETWORKS:
            if nw.in_network(remote_ip):
                return
    except Exception:
        pass
    
    raise PermissionDenied("invalid network")

def macs_restrict_request(func):
    "decorator to check the request object for certain views"
    @wraps(func)
    def check_req(*args,**kwargs):
        # Django Request object is in args[0]
        macs_check_restricted_request(args[0])
        return func(*args,**kwargs)
    return check_req

class IPv4Network(object):
    "representation of an IPv4 network"
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
        
        bin_ip = IPv4Network._ip_to_bin(self._ip)
        self._bin_mask = IPv4Network._mask_to_bin(self._mask)
        self._bin_network = bin_ip & self._bin_mask
        
    def in_network(self, ipaddr):
        "check if the specified IP is in the network"
        try:
            bin_ip = IPv4Network._ip_to_bin(ipaddr)
            bin_net = bin_ip & self._bin_mask
            if bin_net == self._bin_network:
                return True
        except Exception:
            pass        
        return False
    
    def not_in_network(self, ipaddr):
        "opposite of in_network()"
        return not self.in_network(ipaddr)

    @staticmethod
    def _ip_to_bin( ipaddr ):
        """takes an IP address in the form X.X.X.X, where 0 <= X <= 255
        and converts it to a 32-bit unsigned integer
        
        """
        x = list(map(int,ipaddr.split('.')))
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
        mask = int(mask)
        if mask < 8 or mask > 32:
            raise ValueError("the network mask value must be 8 to 32")
        
        return (2**mask-1)<<(32-mask)
    
class IPv6Network(object):
    "representation of an IPv4 network"
    def __init__(self, network):
        "initializer"
        
        if network.find(':') < 0:
            raise ValueError("'%s' is not a valid IPv6 address or network"%network)
        
        x = network.split('/')
        if len(x) == 2:
            self._ip = x[0]
            self._mask = int(x[1])
        else:
            self._ip = x[0]
            self._mask = 128
        
        bin_ip = IPv6Network._ip_to_bin(self._ip)
        self._bin_mask = IPv6Network._mask_to_bin(self._mask)
        self._bin_network = bin_ip & self._bin_mask
        
    def in_network(self, ipaddr):
        "check if the specified IP is in the network"
        try:
            bin_ip = IPv6Network._ip_to_bin(ipaddr)
            bin_net = bin_ip & self._bin_mask
            if bin_net == self._bin_network:
                return True
        except Exception:
            pass
        return False
    
    def not_in_network(self, ipaddr):
        "opposite of in_network()"
        return not self.in_network(ipaddr)

    @staticmethod
    def _ip_to_bin( ipaddr ):
        """takes an IPv6 address and converts it to a
        128-bit unsigned integer
        
        """
        parts = ipaddr.split('::')
        if len(parts) > 2:
            raise ValueError("IPv6 address '{}' is invalid - only one '::' allowed".format(ipaddr))
        elif len(parts) == 1:
            # no double-colon, must be a full IPv6 address with 8 groups
            subparts = ipaddr.split(':')
            if len(subparts) != 8:
                raise ValueError("IPv6 address '{}' is invalid - must have 8 parts when no '::' is present".format(ipaddr))
            return IPv6Network._ip_group_calc(subparts)
        
        # exactly 2 parts exist 
        first = parts[0].split(':')
        last = parts[1].split(':')
        firstn = IPv6Network._ip_group_calc(first)
        lastn = IPv6Network._ip_group_calc(last)
        
        if firstn == 0:
            return lastn
        else:
            return lastn + (firstn << 16*(8-len(first)))
        
    @staticmethod
    def _ip_group_calc( groups ):
        """takes a set of IPv6 address groups and converts
        it to an integer
        """
        if len(groups) == 1 and groups[0] == '':
            # special case
            return 0
        
        shift = 0
        out = 0
        for g in reversed(groups):
            try:
                if len(g) < 1 or len(g) > 4:
                    raise ValueError
                v = int(g,16)            
            except ValueError:
                raise ValueError("invalid IPv6 group '{}'".format(g))
            
            out += v << shift           
            shift += 16
        
        return out
        
    @staticmethod
    def _mask_to_bin( mask ):
        """takes a netmask specifier and converts it to a 32-bit integer
        
        """
        mask = int(mask)
        if mask < 64 or mask > 128:
            raise ValueError("the network mask value must be 64 to 128")
        
        return (2**mask-1)<<(128-mask)
    
class NamedHost(object):
    "representation of a named host"
    
    def __init__(self, host):
        "initializer"
        try:
            socket.getaddrinfo(host,None)
        except socket.gaierror:
            raise ValueError("invalid hostname '{}'".format(host))
        self._host = host        
        
    def in_network(self, ipaddr):
        "check if the specified IP is in the network"
        try:
            # dynamically look up the host's current IP address(es)
            addrlst = []
            for sockinfo in socket.getaddrinfo(self._host,None):
                addrlst.append(sockinfo[4][0])
                
            for nw in compute_networks_and_masks(addrlst):
                if nw.in_network(ipaddr):
                    return True                
        except Exception:
            return False
        return False
    
    def not_in_network(self, ipaddr):
        "opposite of in_network()"
        return not self.in_network(ipaddr)
    
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
            continue
        except Exception:
            pass
            
        try:
            out.append(IPv6Network(nw))
            continue
        except Exception:
            pass
            
        try:
            out.append(NamedHost(nw))
            continue
        except Exception:
            pass
        
        raise ValueError("invalid network/host specification '{}'".format(nw))
    
    return out

# load up _ALLOWED_NETWORKS
_ALLOWED_NETWORKS = compute_networks_and_masks(settings.RESTRICTED_ACCESS_NETWORKS)
    