from django.conf import settings
import sys

# the variables listed here can be overriden by setting the same variables
# with the prefix "MACS_" in the main sites settings.py module
#
# for example, to set "GRACE_PERIOD_DAYS" to 0, set
# "MACS_GRACE_PERIOD_DAYS = 0" in the site-level settings.py file
#

# grace period in days after membership expires
GRACE_PERIOD_DAYS = 5

# door resource ID (should generally be resource 1)
DOOR_RESOURCE_ID = 1

# members that can be granted door access even when the schedule
# dictates that the makerspace is closed, should be a list
MEMBER_TYPES_EXEMPT_FROM_SCHEDULE = ['teacher','administrative']

# IP networks that are allowed access to certain restricted URLs
# in the MACS system (in particular those that only resource manager
# hardware should be accessing)
RESTRICTED_ACCESS_NETWORKS = ['192.168.0.1/16','127.0.0.1']

# update settings from global
def _settings_from_global():
    try:
        me = sys.modules[__name__]
        for name in dir(me):
            if name.isupper() and not name.startswith('_'):
                try:
                    v = getattr(settings,'MACS_'+name)
                    setattr(me,name,v)
                except AttributeError:
                    pass
        
    except Exception:
        pass
    
_settings_from_global()
    
