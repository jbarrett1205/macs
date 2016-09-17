from django.http import HttpResponse, Http404
from django.core.exceptions import PermissionDenied
from django.shortcuts import render, get_object_or_404, redirect
from django import forms as djforms
from django.conf import settings
from django.contrib import messages
from django.core.paginator import Paginator
from django.contrib.auth.decorators import login_required, permission_required, user_passes_test
from django.utils import timezone
from django.contrib.auth import REDIRECT_FIELD_NAME
from django.contrib.auth import views as auth_views
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse

import random
import json
import datetime
import csv as csv_module

from .models import Member, Resource, ResourceAllowed, ResourceAccessLog, DailySchedule, ScheduleException

GRACE_PERIOD_DAYS = settings.MACS_GRACE_PERIOD_DAYS if hasattr(settings,'MACS_GRACE_PERIOD_DAYS') else 5
DOOR_RESOURCE_NAME = settings.MACS_DOOR_RESOURCE_NAME if hasattr(settings,'MACS_DOOR_RESOURCE_NAME') else 'main_door'

# members that can be granted door access
MEMBER_TYPES_EXEMPT_FROM_SCHEDULE = ('teacher','administrative')

# denied access reason codes
ACCESS_DENIED_EXPIRED = 1
ACCESS_DENIED_INACTIVE = 2
ACCESS_DENIED_PERMISSION = 3
ACCESS_DENIED_BAD_KEYCARD = 4
ACCESS_DENIED_SCHEDULE = 5

denied_reason = [
    '',
    'account expired',
    'account inactive',
    'permission denied',
    'invalid keycard',
    'makerspace closed',
]


class MyJSONResponse(HttpResponse):
    "JSON response object"
    
    def __init__(self, data, **kwargs):
        "initializer"
        # initialize the parent class
        if 'content_type' in kwargs:
            # don't allow content_type to be overridden
            del kwargs['content_type']
        super(MyJSONResponse,self).__init__(json.dumps(data), content_type='application/json; charset=utf-8', **kwargs)


def _validate_resource(request, resource_id):
    "validate the resource, throws a PermissionDenied exception if it fails or Http404 exception if the resource ID is invalid"
    resource = get_object_or_404(Resource,pk=resource_id)
    
    if len(resource.secret):
        # need to check the secret key against the
        # "X-resource-key" header that the resource should
        # have sent as part of the request
        h = 'HTTP_X_RESOURCE_KEY'
        if h not in request.META:
            raise PermissionDenied()
        elif request.META[h] != resource.secret:
            raise PermissionDenied()
    else:
        # secret key is not set, no validation to do
        pass
    
    return resource
    
    
def _polulate_validation_dict(resource_id, member, ok=False):
    "populate the dictionary that is returned as a JSON Object"
    
    r = {
        'ok':0,
        'first_name':'',
        'last_name':'',
        'user_id':'',
        'resource_id':int(resource_id),
        'access_card_id':'',
        'expires':'1999/01/01',
        'notok_reason':'',
        'type':'',
    }
    
    if member is not None:
        r['first_name'] = member.first_name
        r['last_name'] = member.last_name
        r['user_id'] = member.username
        r['access_card_id'] = member.keycard
        r['expires'] = member.expires.strftime('%Y/%m/%d')
        r['type'] = member.membership_type
    
    if ok:
        r['ok'] = 1
    
    return r

def macs_default_context( c=None ):
    "create the default context object (dictionary)"
    r = {
        'redirect_field_name':REDIRECT_FIELD_NAME,
    }
    
    if c is not None:
        r.update(c)
    
    return r

def _schedule_allowed(member):
    "check the access schedule to determine if the access should be allowed"
    # always return true for member types that are exempt from the schedule
    if member.membership_type in MEMBER_TYPES_EXEMPT_FROM_SCHEDULE:
        return True
    
    now = datetime.datetime.now()
    today = now.date()
    cur_time = now.time()
    
    # first check for exceptions since those override the daily schedule
    for exc in ScheduleException.objects.filter(date__exact=today):
        if cur_time >= exc.start_time and cur_time <= exc.end_time:
            # we are within this exception window
            return exc.open
    
    # next check the daily schedule for the current day of the week
    for daily in DailySchedule.objects.filter(day__exact=today.isoweekday()):
        if cur_time >= daily.start_time and cur_time <= daily.end_time:
            # we are within this daily window
            return True
    
    # couldn't match to a daily schedule window
    return False
    

###########################################################################################################
###########################################################################################################
#######                                   main index                                                ####### 
###########################################################################################################
###########################################################################################################

def index(request):
    "landing point for MACS"
    return render(request,'macs/index.htm',macs_default_context())

def logout(request):
    "logout view"    
    return auth_views.logout(request,template_name='macs/logout.htm')
    
###########################################################################################################
###########################################################################################################
#######             REST+JSON views for resources to validate users against                         ####### 
###########################################################################################################
###########################################################################################################

def json_download_members(request, resource_id):
    "download a list of all valid users for the given resource"
    
    if request.method != 'GET':
        return HttpResponse(status=405)  # HTTP METHOD NOT ALLOWED
        
    # validate the resource first
    resource = _validate_resource(request,resource_id)
    
    # create a list of all members with access to the resource
    lst = [x.member for x in ResourceAllowed.objects.filter(resource__id=resource_id)]
    
    # create the return list
    r = []
    for member in lst:
        # check that the member account is valid
        if not member.is_active:
            # account inactive
            pass
        elif (member.expires - datetime.date.today()).days < -GRACE_PERIOD_DAYS:
            # account expired
            pass
        else:
            # member account is valid, add it to the list
            r.append(_polulate_validation_dict(resource_id,member,True))

    # convert to JSON and return
    return MyJSONResponse(r)

def json_validate_member(request, resource_id, keycard_id):
    "check if the user specified by the given ID card has permission for the passed resource ID"
    
    if request.method != 'GET':
        return HttpResponse(status=405)  # HTTP METHOD NOT ALLOWED
    
    # validate the resource first
    resource = _validate_resource(request,resource_id)
    
    # locate the member by the keycard ID
    try:
        member = Member.objects.get(keycard__iexact=keycard_id)
    except Member.DoesNotExist:
        member = None
        
    # populate the initial return structure
    r = _polulate_validation_dict(resource_id,member)
        
    why_denied = 0    
    if member is not None:
        # check that the member account is valid
        if not member.is_active:
            why_denied = ACCESS_DENIED_INACTIVE
        elif (member.expires - datetime.date.today()).days < -GRACE_PERIOD_DAYS:
            why_denied = ACCESS_DENIED_EXPIRED
        else:
            # first check the access schedule to see that the member
            # is allowed to access at time time
            if _schedule_allowed(member):
                # next check for member access to the specified resource
                result = member.resources.filter(id=resource_id)
                if len(result):
                    r['ok'] = 1
                else:
                    why_denied = ACCESS_DENIED_PERMISSION
            else:
                why_denied = ACCESS_DENIED_SCHEDULE
    else:
        # no member matched the keycard, fill in the passed keycard ID
        # and set the notok_reason field
        r['access_card_id'] = keycard_id
        why_denied = ACCESS_DENIED_BAD_KEYCARD
    
    r['notok_reason'] = denied_reason[why_denied]
    
    # create a log entry
    try:
        logentry = ResourceAccessLog(keycard=keycard_id,member=member,resource=resource,allowed=bool(r['ok']),reason_code=why_denied)
        logentry.save()
    except Exception:
        pass
        
    # convert to JSON and return
    return MyJSONResponse(r)
        
###########################################################################################################
###########################################################################################################
#######                  member account creation and modification views                             ####### 
###########################################################################################################
###########################################################################################################

class CreateEditMemberForm(djforms.ModelForm):
    "form for creating and editing member data"
    
    class Meta:
        model = Member
        fields = ['first_name','last_name','email','username','membership_type','keycard','expires','billing_id','comments']
    
    def clean_keycard(self):
        "ensure that non-blank keycard fields are unique in the database"
        keycard = self.cleaned_data['keycard'].strip()
        if not len(keycard):
            # blank keycard entries are fine, they won't match any queries
            # this exists so that member accounts can be created before a keycard
            # is assigned
            return u''
            
        try:
            m = Member.objects.get(keycard__iexact=keycard)
            if self.instance.id != m.id:
                # uh oh, another member has this keycard assigned
                name = m.first_name+' '+m.last_name
                raise djforms.ValidationError("This keycard is already assigned to '%s'. Remove it from that account first."%name)
        except Member.DoesNotExist:
            # good, no other member has this keycard assigned to them
            pass
        except Member.MultipleObjectsReturned:
            # this is really bad, there are already more than one member assigned
            # to this keycard, this should not be possible unless the database
            # is manually edited
            raise djforms.ValidationError("DANGER WILL ROBINSON! This keycard is assigned to multiple members already!")
            
        return keycard
    
@permission_required('macs.change_member')
def member_create(request):
    "create a new makerspace member account"
    
    context = macs_default_context()
    
    if request.method == 'POST':
        form = CreateEditMemberForm(request.POST,request.FILES)    
        if form.is_valid():
            door = None
            try:
                # make sure that the "door" resource exists
                door = Resource.objects.get(name__exact=DOOR_RESOURCE_NAME)
            except Resource.DoesNotExist:
                messages.add_message(request,messages.ERROR,'The main door resource must exist and must be named `%s`.'%DOOR_RESOURCE_NAME)
            
            if door:
                # create the member account
                member = form.save(commit=False)
                # set a random password, members can change it later using
                # the reset password functionality
                pw = ''
                for _ in range(20):
                    pw += random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
                member.set_password(pw)
                member.save()
                
                # create default access to the "door" resource
                ra = ResourceAllowed(member=member,resource=door,trainer='n/a')
                ra.save()
                
                ##### TODO: set up e-mails to initialize the login password
                
                
                
                return redirect(member)    
    else:
        # create an un-bound form when the request is not a POST
        form = CreateEditMemberForm()
        
    context['form'] = form
    return render(request,'macs/member_create.htm',context)
    
@permission_required('macs.change_member')
def member_list(request):
    "view a member account"
    context = macs_default_context({'members':Member.objects.all()})
    return render(request,'macs/member_list.htm',context)
    
@permission_required('macs.change_member')
def member_view(request, member_id):
    "view a member account"
    member = get_object_or_404(Member,pk=member_id)
    context = macs_default_context({'member':member})
    return render(request,'macs/member_view.htm',context)
    
@permission_required('macs.change_member')
def member_edit(request, member_id):
    "edit a member account"
    member = get_object_or_404(Member,pk=member_id)    
    context = macs_default_context({'member':member})
    
    if request.method == 'POST':
        form = CreateEditMemberForm(request.POST,request.FILES,instance=member)
    
        if form.is_valid():
            form.save()
            return redirect(member)
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')
            
    else:
        form = CreateEditMemberForm(instance=member)
    
    context['form'] = form
    
    return render(request,'macs/member_edit.htm',context)


###########################################################################################################
###########################################################################################################
#######                     resource creation and modification views                                ####### 
###########################################################################################################
###########################################################################################################

class CreateEditResourceForm(djforms.ModelForm):
    "form for creating and editing member data"
    
    class Meta:
        model = Resource
        fields = ['name','description','secret','cost_per_hour']
    

@permission_required('macs.change_resource')
def resource_create(request):
    "create a new resource (door, tool, etc)"
        
    if request.method == 'POST':
        form = CreateEditResourceForm(request.POST,request.FILES)    
        if form.is_valid():
            # create the resource
            resource = form.save()
            return redirect(resource)
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')        
    
    else:
        # create an un-bound form when the request is not a POST
        form = CreateEditResourceForm()
        
    context = macs_default_context({'form': form})
    return render(request,'macs/resource_create.htm',context)
    
@permission_required('macs.change_resource')
def resource_list(request):
    "list all resources"
    context = macs_default_context({'resources':Resource.objects.all()})
    return render(request,'macs/resource_list.htm',context)
    
@permission_required('macs.change_resource')
def resource_view(request, resource_id):
    "view a resource"
    resource = get_object_or_404(Resource,pk=resource_id)    
    context = macs_default_context(
        {'resource':resource,
        'members_allowed':ResourceAllowed.objects.filter(resource__id=resource.id).order_by('member__last_name','member__first_name'),
        })
    return render(request,'macs/resource_view.htm',context)
    
    
@permission_required('macs.change_resource')
def resource_edit(request, resource_id):
    "edit a resource"
    resource = get_object_or_404(Resource,pk=resource_id)    
    context = macs_default_context({'resource':resource})
    
    if request.method == 'POST':
        form = CreateEditResourceForm(request.POST,request.FILES,instance=resource)
    
        if form.is_valid():
            resource = form.save()
            return redirect(resource)
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')
            
    else:
        form = CreateEditResourceForm(instance=resource)
    
    context['form'] = form
    return render(request,'macs/resource_edit.htm',context)

###########################################################################################################
###########################################################################################################
#######                     views for allowing users to access resources                            ####### 
###########################################################################################################
###########################################################################################################

@permission_required('macs.change_member')
def add_resource_access(request, member_id):
    "assign a mmeber access to a new resource"
    member = get_object_or_404(Member,pk=member_id)    
    context = macs_default_context({'member':member})
    
    already_have_resource_ids = list(x.resource.id for x in ResourceAllowed.objects.filter(member__id=member.id))
    qs = Resource.objects.all().exclude(id__in=already_have_resource_ids)
    
    class AddResourceAccessForm(djforms.Form):
        "form to add a resource to a member"
        
        resource = djforms.ModelChoiceField(queryset=qs)
        trainer = djforms.CharField(max_length=64)
        comment = djforms.CharField(max_length=255,required=False)
        
    if request.method == 'POST':
        form = AddResourceAccessForm(request.POST,request.FILES)
        if form.is_valid():
            d = form.cleaned_data
            ra = ResourceAllowed(member=member,resource=d['resource'],trainer=d['trainer'],comment=d['comment'])
            ra.save()
            
            return redirect(member)
    else:
        form = AddResourceAccessForm()
        
    context['form'] = form
    
    return render(request,'macs/member_add_resource.htm',context)
    
###########################################################################################################
###########################################################################################################
#######                     views for allowing users to view reports                                ####### 
###########################################################################################################
###########################################################################################################

@permission_required('macs.change_member')
def report_access_log(request):
    "view the access log for resources"
    ninety_days_ago = timezone.now() - datetime.timedelta(days=90)
    qs = ResourceAccessLog.objects.filter(timestamp__gt=ninety_days_ago)
    
    if request.GET.get('csv',''):
        # CSV file download
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="access-log-'+datetime.datetime.now().strftime('%Y%m%d')+'.csv"'
        writer = csv_module.writer(response)
        writer.writerow(['Timestamp','Resource ID','Resource Name','Keycard','Member ID','Member Name','Allowed','Reason Code'])
        for log in qs:
            member_id, member_name = '', ''
            if log.member:
                member_id, member_name = str(log.member.id), log.member.get_full_name()
            allowed = '1' if log.allowed else '0'
            fields = [log.timestamp.strftime('%Y/%m/%d %H:%M:%S'),str(log.resource.id),log.resource.name,log.keycard,member_id,member_name,allowed,str(log.reason_code)]
            writer.writerow([f.encode('cp1252','replace') for f in fields])      
        return response    
    
    # normal response
    pager = Paginator(qs,100)
    page = request.GET.get('p','1')
    try:
        p = pager.page(int(page))
    except Exception:
        p = pager.page(1)
        
    context = macs_default_context({'page':p})
    return render(request,'macs/report_access_log.htm',context)
    
    
###########################################################################################################
###########################################################################################################
#######                     views to set and edit the Makerspace access schedule                    ####### 
###########################################################################################################
###########################################################################################################
    
class AddEditDailyScheduleForm(djforms.ModelForm):
    "form for creating and editing member data"
    
    class Meta:
        model = DailySchedule
        fields = ['day','start_time','end_time']
    
    def clean(self):
        "make sure the start time is before the end time"
        if self.cleaned_data['end_time'] <= self.cleaned_data['start_time']:
            raise djforms.ValidationError("'end_time' must be greater than 'start_time'")
        return self.cleaned_data
    
class AddEditScheduleExceptionForm(djforms.ModelForm):
    "form for creating and editing member data"
    
    class Meta:
        model = ScheduleException
        fields = ['date','start_time','end_time','open','comment']
    
    def clean(self):
        "make sure the start time is before the end time"
        if self.cleaned_data['end_time'] <= self.cleaned_data['start_time']:
            raise djforms.ValidationError("'end_time' must be greater than 'start_time'")
        return self.cleaned_data
    
@permission_required('macs.change_member')
def schedule_show(request):
    "show the current schedule"
    today = datetime.date.today()
    yesterday = today - datetime.timedelta(days=1)
    thirty_days_future = today + datetime.timedelta(days=31)
    
    context = macs_default_context({
        'daily_schedule':DailySchedule.objects.all(),
        'upcoming_exceptions':ScheduleException.objects.filter(date__gt=yesterday).filter(date__lt=thirty_days_future),
        })

    return render(request,'macs/schedule_show.htm',context)

@permission_required('macs.change_member')
def schedule_add_daily(request):
    "add a daily schedule window"
    if request.method == 'POST':
        form = AddEditDailyScheduleForm(request.POST,request.FILES)    
        if form.is_valid():
            # create the schedule
            schedule = form.save()
            return redirect('macs.views.schedule_show')
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')        
    
    else:
        # create an un-bound form when the request is not a POST
        form = AddEditDailyScheduleForm()
        
    context = macs_default_context({'form': form})
    return render(request,'macs/schedule_add_daily.htm',context)

@permission_required('macs.change_member')
def schedule_edit_daily(request, sch_id):
    "edit a daily schedule window"
    schedule = get_object_or_404(DailySchedule,pk=sch_id)

    if request.method == 'POST':
        form = AddEditDailyScheduleForm(request.POST,request.FILES,instance=schedule)    
        if form.is_valid():
            # create the schedule
            schedule = form.save()
            return redirect('macs.views.schedule_show')
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')        
    
    else:
        # create an un-bound form when the request is not a POST
        form = AddEditDailyScheduleForm(instance=schedule)
        
    context = macs_default_context({'form': form})
    return render(request,'macs/schedule_edit_daily.htm',context)

@permission_required('macs.change_member')
def schedule_remove_daily(request, sch_id):
    "delete a daily schedule window"
    schedule = get_object_or_404(DailySchedule,pk=sch_id)
    
    if request.method == 'POST':
        try:
            del_id = int(request.POST['id'])
            if del_id == int(sch_id):
                schedule.delete()
                return redirect('macs.views.schedule_show')
            else:
                raise ValueError('Validation failed.')
        
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to delete -> "+str(e))

    context = macs_default_context({'schedule':schedule})
    return render(request,'macs/schedule_remove_daily.htm',context)


@permission_required('macs.change_member')
def schedule_add_exception(request):
    "add a daily schedule window"
    if request.method == 'POST':
        form = AddEditScheduleExceptionForm(request.POST,request.FILES)    
        if form.is_valid():
            # create the schedule
            schedule = form.save()
            return redirect('macs.views.schedule_show')
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')        
    
    else:
        # create an un-bound form when the request is not a POST
        form = AddEditScheduleExceptionForm()
        
    context = macs_default_context({'form': form})
    return render(request,'macs/schedule_add_exception.htm',context)

@permission_required('macs.change_member')
def schedule_edit_exception(request, sch_id):
    "edit a schedule exception"
    schedule = get_object_or_404(ScheduleException,pk=sch_id)

    if request.method == 'POST':
        form = AddEditScheduleExceptionForm(request.POST,request.FILES,instance=schedule)    
        if form.is_valid():
            # create the schedule
            schedule = form.save()
            return redirect('macs.views.schedule_show')
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')        
    
    else:
        # create an un-bound form when the request is not a POST
        form = AddEditScheduleExceptionForm(instance=schedule)
        
    context = macs_default_context({'form': form})
    return render(request,'macs/schedule_edit_exception.htm',context)

@permission_required('macs.change_member')
def schedule_remove_exception(request, sch_id):
    "delete a schedule exception"
    schedule = get_object_or_404(ScheduleException,pk=sch_id)
    
    if request.method == 'POST':
        try:
            del_id = int(request.POST['id'])
            if del_id == int(sch_id):
                schedule.delete()
                return redirect('macs.views.schedule_show')
            else:
                raise ValueError('Validation error.')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to delete -> "+str(e))

    context = macs_default_context({'schedule':schedule})
    return render(request,'macs/schedule_remove_exception.htm',context)









    
    
    
    
    
