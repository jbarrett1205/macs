from django.conf.urls import include, url
from . import views

urlpatterns = (
    url(r'^$',views.index,name="macs_home"),
    url(r'^q/(\d+)/$',views.json_download_members),
    url(r'^q/(\d+)/([a-fA-F0-9]{2,})/$',views.json_validate_member),
    url(r'^members/create/$',views.member_create),
    url(r'^members/$',views.member_list),
    url(r'^members/(\d+)/$',views.member_view),
    url(r'^members/(\d+)/edit/$',views.member_edit),
    url(r'^members/(\d+)/add_resource/$',views.add_resource_access),
    url(r'^members/(\d+)/manage_keycards/$',views.member_manage_keycards),
    url(r'^resources/create/$',views.resource_create),
    url(r'^resources/(\d+)/$',views.resource_view),
    url(r'^resources/$',views.resource_list),
    url(r'^resources/(\d+)/edit/$',views.resource_edit),
    url(r'^keycards/$',views.keycard_manage_all),
    url(r'^keycards/(\d+)/$',views.keycard_manage),
    url(r'^keycards/(\d+)/set_active/$',views.keycard_set_active),
    url(r'^keycards/(\d+)/set_inactive/$',views.keycard_set_inactive),
    url(r'^keycards/(\d+)/unassign/$',views.keycard_unassign),
    url(r'^keycards/upload/$',views.keycard_csv_upload),
    url(r'^reports/access_log/$',views.report_access_log),
    url(r'^schedule/$',views.schedule_show),
    url(r'^schedule/daily/add/$',views.schedule_add_daily),
    url(r'^schedule/daily/(\d+)/edit/$',views.schedule_edit_daily),
    url(r'^schedule/daily/(\d+)/delete/$',views.schedule_remove_daily),
    url(r'^schedule/exc/add/$',views.schedule_add_exception),
    url(r'^schedule/exc/(\d+)/edit/$',views.schedule_edit_exception),
    url(r'^schedule/exc/(\d+)/delete/$',views.schedule_remove_exception),
    
)
