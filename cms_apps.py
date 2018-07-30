from cms.app_base import CMSApp
from cms.apphook_pool import apphook_pool
from django.utils.translation import ugettext_lazy as _


class MACSApphook(CMSApp):
    app_name = "macs"
    name = _("MACS Application")

    def get_urls(self, page=None, language=None, **kwargs):
        return ["macs.urls"]

apphook_pool.register(MACSApphook)  # register the application