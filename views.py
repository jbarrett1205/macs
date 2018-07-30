from django.http import HttpResponse, Http404
from django.core.exceptions import PermissionDenied
from django.shortcuts import render, get_object_or_404, redirect
from django import forms as djforms
from django.contrib import messages
from django.core.paginator import Paginator
from django.core.exceptions import ValidationError
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
import re
from StringIO import StringIO
import logging

from .constants import *
from .models import (Member, Keycard, Resource, ResourceAllowed, ResourceAccessLog,
    DailySchedule, ScheduleException, ActivityLog, keycard_number_ok)
from . import settings
from .ip_utils import macs_restrict_request


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
            raise PermissionDenied
        elif request.META[h] != resource.secret:
            raise PermissionDenied
    else:
        # secret key is not set, no validation to do
        pass
    
    return resource
    
    
def _polulate_validation_dict(resource_id, keycard_id, member, ok=False):
    "populate the dictionary that is returned as a JSON Object"
    
    r = {
        'ok':0,
        'first_name':'',
        'last_name':'',
        'user_id':'',
        'resource_id':int(resource_id),
        'access_card_id':keycard_id,
        'expires':'1999/01/01',
        'notok_reason':'',
        'type':'',
        'incognito':1,
        'resource_locked':0,
    }
    
    if member is not None:
        r['first_name'] = member.first_name
        r['last_name'] = member.last_name
        r['user_id'] = member.username
        r['expires'] = member.expires.strftime('%Y/%m/%d')
        r['type'] = member.membership_type
        r['incognito'] = 1 if member.incognito else 0
    
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
    if member.membership_type in settings.MEMBER_TYPES_EXEMPT_FROM_SCHEDULE:
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

def _log_activity(request, model, action, details=''):
    "create a log of activity performed in the MACS system"
    try:
        user = request.user
        id = model.id
        
        if id is None:  
            raise ValueError("model ID is not set (model not saved?)")
        
        if action not in ('create','modify','delete','assign'):
            raise ValueError("invalid 'action'")
        
        data = {
            'user':user,
            'model_name':model._meta.model_name,
            'model_id':id,
            'action':action,
            'details':details,    
        }
        log = ActivityLog(**data)
        log.save()
    
    except Exception as e:
        # do something to log the issue
        log = logging.getLogger('macs.log_activity')
        log.error('activity log error => %s'%e)
    

###########################################################################################################
###########################################################################################################
#######                                   main index                                                ####### 
###########################################################################################################
###########################################################################################################

@login_required
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

@macs_restrict_request
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
        elif (member.expires - datetime.date.today()).days < -settings.GRACE_PERIOD_DAYS:
            # account expired
            pass
        else:
            # member account is valid, add it to the list
            # add an entry for each keycard that is tied to the member
            for keycard in member.keycard_set.all():
                r.append(_polulate_validation_dict(resource_id,keycard.number,member,True))

    # convert to JSON and return
    return MyJSONResponse(r)

@macs_restrict_request
def json_validate_member(request, resource_id, keycard_id):
    "check if the user specified by the given ID card has permission for the passed resource ID"
    
    if request.method != 'GET':
        return HttpResponse(status=405)  # HTTP METHOD NOT ALLOWED
    
    # validate the resource first
    resource = _validate_resource(request,resource_id)
    
    # locate the member by the keycard ID
    try:
        keycard = Keycard.objects.get(number__iexact=keycard_id)
        member = keycard.member
    except Keycard.DoesNotExist:
        keycard = None
        member = None
    
    # check to see if the keycard is a special "lockout card"
    if keycard and keycard.lockout_card and keycard.active and resource.id != settings.DOOR_RESOURCE_ID:
        # changing the state of a resource based on a GET is not strictly
        # a desirable thing in terms of web "standards", but it's reasonable
        # in this case as it's sort of a security lockout
        resource.locked = True
        resource.save()        
        
    # populate the initial return structure, at this point the structure is
    # as full as it can be and the only things left to determine are the
    # state of the 'ok' flag and the 'notok_reason' which we will
    # figure out in the next block of code
    r = _polulate_validation_dict(resource_id,keycard_id,member)
    
    # figure out whether access should be allowed
    why_denied = 0
    if resource.locked:
        why_denied = ACCESS_DENIED_RESOURCE_LOCKED
        r['resource_locked'] = 1
    else:
        if keycard is not None:
            if member is not None:
                # check that the member account is valid
                if not member.is_active:
                    why_denied = ACCESS_DENIED_INACTIVE
                elif (member.expires - datetime.date.today()).days < -settings.GRACE_PERIOD_DAYS:
                    why_denied = ACCESS_DENIED_EXPIRED
                elif not keycard.active:
                    why_denied = ACCESS_DENIED_KEYCARD_INACTIVE       
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
                # keycard has no member assigned to it
                why_denied = ACCESS_DENIED_UNASSIGNED_KEYCARD
        else:
            # keycard is not in the database
            why_denied = ACCESS_DENIED_BAD_KEYCARD
    
    # set the denied reason (empty string if access allowed)
    r['notok_reason'] = access_denied_reason[why_denied]
    
    # create a log entry
    try:
        logentry = ResourceAccessLog(keycard=keycard_id,member=member,resource=resource,allowed=bool(r['ok']),reason_code=why_denied)
        logentry.save()
    except Exception:
        pass
        
    # convert to JSON and return
    return MyJSONResponse(r)
        
@macs_restrict_request
def json_get_schedule(request, year=None, month=None, day=None):
    "get the makerspace schedule for a given day"
    
    if request.method != 'GET':
        return HttpResponse(status=405)  # HTTP METHOD NOT ALLOWED
    
    if year is None:
        # no date passed in, use today
        query_date = datetime.date.today()
    else:
        # create a date from the passed in date parts
        query_date = datetime.date(int(year),int(month),int(day))    

    # schedule exceptions
    exc = []
    for v in ScheduleException.objects.filter(date__exact=query_date):
        exc.append({
            'start_time':v.start_time.strftime('%H:%M:%S'),
            'end_time':v.end_time.strftime('%H:%M:%S'),
            'open':v.open,
            })
    
    # daily schedule
    daily = []
    for v in DailySchedule.objects.filter(day__exact=query_date.isoweekday()):
        daily.append({
            'start_time':v.start_time.strftime('%H:%M:%S'),
            'end_time':v.end_time.strftime('%H:%M:%S'),
            })
    
    r = {
        'exceptions':exc,
        'daily':daily,
    }
    
    # convert to JSON and return
    return MyJSONResponse(r)    
    
@macs_restrict_request
def json_resource_status(request, resource_id):
    "check the status of a resource"
    
    if request.method != 'GET':
        return HttpResponse(status=405)  # HTTP METHOD NOT ALLOWED
    
    # validate the resource first
    resource = _validate_resource(request,resource_id)
    
    # generate the response
    r = {
        'resource_id':int(resource_id),
        'name':resource.name,
        'description':resource.description,
        'resource_locked':1 if resource.locked else 0,
    }
    
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
        fields = ['first_name','last_name','email','username','membership_type','expires','billing_id','incognito','comments']

class CreateAssignKeycardForm(djforms.Form):
    "create a new keycard or assign an existing one"
    KEYCARD_CHOICES = [
        ('0','No Keycard'),
        ('1','Create New Keycard'),
        ('2','Select From Existing Keycards'),
    ]
    KEYCARD_CHOICES2 = [
        ('1','Create New Keycard'),
        ('2','Select From Existing Keycards'),
    ]
    number = djforms.CharField(max_length=64,required=False)
    select_keycard = djforms.ModelChoiceField(queryset=Keycard.objects.filter(member__isnull=True,active=True,lockout_card=False),required=False)
    
    def __init__(self, include_no_keycard, *args, **kwargs):
        "allow changing of which action fields are allowed"
        super(CreateAssignKeycardForm,self).__init__(*args,**kwargs)
        if include_no_keycard:
            c = self.KEYCARD_CHOICES
        else:
            c = self.KEYCARD_CHOICES2
        self.fields['action'] = djforms.ChoiceField(choices=c)
        
    def clean_action(self):
        "turn the action into an integer"
        try:
            action = int(self.cleaned_data['action'])
        except Exception:
            raise djforms.ValidationError("Invalid action.")
        return action
    
    def clean(self):
        "check that necessary fields are filled out"
        action = self.cleaned_data['action']
        if action == 0:
            pass        
        elif action == 1:
            # check that the number field is valid
            try:
                keycard_number_ok(self.cleaned_data['number'])
            except ValidationError as ex:
                self.add_error('number',ex)
        elif action == 2:
            # check that the select_keycard field is valid
            if not isinstance(self.cleaned_data['select_keycard'],Keycard):
                self.add_error('select_keycard',djforms.ValidationError('Invalid keycard selected.'))
        
        return self.cleaned_data

        
@permission_required('macs.change_member')
def member_create(request):
    "create a new makerspace member account"
    
    context = macs_default_context()
    
    if request.method == 'POST':
        form = CreateEditMemberForm(request.POST,request.FILES)
        keycard_form = CreateAssignKeycardForm(True,request.POST,request.FILES)
        if form.is_valid() and keycard_form.is_valid():
            door = None
            try:
                # make sure that the "door" resource exists
                door = Resource.objects.get(pk=settings.DOOR_RESOURCE_ID)
            except Resource.DoesNotExist:
                messages.add_message(request,messages.ERROR,'The main door resource must exist with resource id `%d`.'%settings.DOOR_RESOURCE_ID)
            
            if door:
                # create the member account
                member = form.save(commit=False)
                # set a random password, members can change it later using
                # the reset password functionality
                pw = ''
                for _ in range(20):
                    pw += random.choice('abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ123456789')
                member.set_password(pw)
                member.save()
                _log_activity(request,member,'create','name = [%s], id = [%d], expires = [%s]'%(member.get_full_name(),member.id,member.expires.strftime('%Y/%m/%d')))
                
                # create default access to the "door" resource
                ra = ResourceAllowed(member=member,resource=door,trainer='n/a')
                ra.save()
                
                # create or assign keycards
                keycard_data = keycard_form.cleaned_data
                action = keycard_data['action']
                if action == 1:
                    # create a new keycard and attach the member to it
                    keycard = Keycard(number=keycard_data['number'],member=member,active=True)
                    keycard.save()                                    
                    _log_activity(request,keycard,'create','number = [%s], id = [%d]'%(keycard.number,keycard.id))
                    _log_activity(request,member,'assign','keycard [%s] assigned to member [%s]'%(keycard.number,member.get_full_name()))
                elif action == 2:
                    # keycard selected, attach the member to it
                    keycard = keycard_data['select_keycard']
                    if keycard.lockout_card:
                        messages.add_message(request,messages.WARNING,'`Lockout` keycard cannot be assigned to a member account.')
                    else:
                        keycard.member = member
                        keycard.save()
                        _log_activity(request,member,'assign','keycard [%s] assigned to member [%s]'%(keycard.number,member.get_full_name()))
                
                return redirect(member)
    else:
        # create an un-bound forms when the request is not a POST
        form = CreateEditMemberForm()
        keycard_form = CreateAssignKeycardForm(True)
        
    context['form'] = form
    context['keycard_form'] = keycard_form
    return render(request,'macs/member_create.htm',context)
    
@permission_required('macs.change_member')
def member_list(request):
    "list all members"
    which = request.GET.get('w','all')
    if which == 'expired':
        qs = Member.objects.filter(expires__lt=datetime.date.today())
    elif which == 'active':
        qs = Member.objects.filter(expires__gte=datetime.date.today())
    else:
        qs = Member.objects.all()
        which = 'all'
    context = macs_default_context({'members':qs,'which':which})
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
            if form.has_changed():
                member = form.save()
                if not member.is_active and member.expires > datetime.date.today():
                    # re-activate accounts that have been disabled if the
                    # memebership expiration date is in the future
                    member.is_active = True
                    member.save()
                extra = ''
                if 'expires' in form.changed_data:
                    extra = ' -> new expires = [%s]'%member.expires.strftime('%Y/%m/%d')
                _log_activity(request,member,'modify','changed fields: %s'%(', '.join(form.changed_data))+extra)
            return redirect(member)
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')
            
    else:
        form = CreateEditMemberForm(instance=member)
    
    context['form'] = form
    
    return render(request,'macs/member_edit.htm',context)

@permission_required('macs.change_member')
def add_resource_access(request, member_id):
    "assign a mmeber access to a new resource"
    member = get_object_or_404(Member,pk=member_id)    
    context = macs_default_context({'member':member})
    
    already_have_resource_ids = list(x.resource.id for x in ResourceAllowed.objects.filter(member__id=member.id))
    avail_rsc = list(Resource.objects.all().exclude(id__in=already_have_resource_ids))
    
    class AddResourceAccessForm(djforms.Form):
        "form to add a resource to a member"
        
        def __init__(self, avail_resources, *args, **kwargs):
            "initializer"
            super(AddResourceAccessForm,self).__init__(*args,**kwargs)
            self.resource_field_names = []
            for r in avail_resources:
                n = 'resource_%d'%r.id
                self.fields[n] = djforms.BooleanField(label=r.name,required=False,initial=False)
                self.resource_field_names.append(n)
            
        trainer = djforms.CharField(max_length=64)
        comment = djforms.CharField(max_length=255,required=False)
        
        def get_resource_fields(self):
            "return the resource fields in a list so that they can be iterated over in the display template"
            r = []
            for n in self.resource_field_names:
                r.append(self[n])            
            return r
        
    if request.method == 'POST':
        form = AddResourceAccessForm(avail_rsc,request.POST,request.FILES)
        if form.is_valid():
            d = form.cleaned_data
            for r in avail_rsc:
                n = 'resource_%d'%r.id
                if n in d and d[n]:
                    ra = ResourceAllowed(member=member,resource=r,trainer=d['trainer'],comment=d['comment'])
                    ra.save()
                    _log_activity(request,ra,'create','member [%s] assigned access to resource [%s]'%(ra.member.get_full_name(),ra.resource.name))
            
            return redirect(member)
    else:
        form = AddResourceAccessForm(avail_rsc)
        
    context['form'] = form
    
    return render(request,'macs/member_add_resource.htm',context)
    
@permission_required('macs.change_member')
def remove_resource_access(request, member_id, resource_id):
    "remove member access to a resource"
    resource_allowed = get_object_or_404(ResourceAllowed,member__id=member_id,resource__id=resource_id)    
    context = macs_default_context({'resource_allowed':resource_allowed})    
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == settings.DOOR_RESOURCE_ID:
                raise ValueError("main door resource access cannot be removed - invalidate the account or keycard instead")
            if req_id == resource_allowed.id:
                _log_activity(request,resource_allowed,'delete','member [%s] access revoked to resource [%s]'%(resource_allowed.member.get_full_name(),resource_allowed.resource.name))
                resource_allowed.delete()
                return redirect(resource_allowed.member)
            else:
                raise ValueError('Validation error.')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to remove resource access -> "+str(e))
    
    return render(request,'macs/member_remove_resource.htm',context)
    
@permission_required('macs.change_member')
def member_manage_keycards(request, member_id):
    "edit a member account"
    member = get_object_or_404(Member,pk=member_id)    
    context = macs_default_context({'member':member})
    
    if request.method == 'POST':
        form = CreateAssignKeycardForm(False,request.POST,request.FILES)
        if form.is_valid():
            keycard_data = form.cleaned_data
            action = keycard_data['action']
            if action == 1:
                # create a new keycard and attach the member to it
                keycard = Keycard(number=keycard_data['number'],member=member,active=True)
                keycard.save()                                    
                _log_activity(request,keycard,'create','number = [%s], id = [%d]'%(keycard.number,keycard.id))
                _log_activity(request,member,'assign','keycard [%s] assigned to member [%s]'%(keycard.number,member.get_full_name()))
            elif action == 2:
                # keycard selected, attach the member to it
                keycard = keycard_data['select_keycard']
                if keycard.lockout_card:
                    messages.add_message(request,messages.WARNING,'`Lockout` keycard cannot be assigned to a member account.')
                else:
                    keycard.member = member
                    keycard.save()
                    _log_activity(request,member,'assign','keycard [%s] assigned to member [%s]'%(keycard.number,member.get_full_name()))
            
            return redirect(request.get_full_path())
    else:
        form = CreateAssignKeycardForm(False)
    
    context['form'] = form
    
    return render(request,'macs/member_manage_keycards.htm',context)    

###########################################################################################################
###########################################################################################################
#######                           keycard management view                                           ####### 
###########################################################################################################
###########################################################################################################

@permission_required('macs.change_member')
def keycard_manage_all(request):
    "manage all keycards in the system"
    context = macs_default_context({
        'lockout':Keycard.objects.filter(member__isnull=True,lockout_card=True),
        'unassigned':Keycard.objects.filter(member__isnull=True,lockout_card=False),
        'assigned':Keycard.objects.filter(member__isnull=False).order_by('member__last_name','member__first_name'),
    })

    return render(request,'macs/keycard_manage_all.htm',context)

@permission_required('macs.change_member')
def keycard_manage(request, key_id):
    "manage an individual keycard"
    keycard = get_object_or_404(Keycard,pk=key_id)
    return render(request,'macs/keycard_manage.htm',macs_default_context({'keycard':keycard}))
    
@permission_required('macs.change_member')
def keycard_set_inactive(request, key_id):
    "set a keycard to be inactive"
    keycard = get_object_or_404(Keycard,pk=key_id)
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == int(key_id):
                keycard.active = False
                keycard.save()
                _log_activity(request,keycard,'modify','number = [%s], active = [False]'%keycard.number)
                return redirect(keycard)
            else:
                raise ValueError('validation error')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to inactivate keycard -> "+str(e))
        
    return render(request,'macs/keycard_set_inactive.htm',macs_default_context({'keycard':keycard}))

@permission_required('macs.change_member')
def keycard_set_active(request, key_id):
    "set a keycard to be active"
    keycard = get_object_or_404(Keycard,pk=key_id)
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == int(key_id):
                keycard.active = True
                keycard.save()
                _log_activity(request,keycard,'modify','number = [%s], active = [True]'%keycard.number)
                return redirect(keycard)
            else:
                raise ValueError('validation error')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to activate keycard -> "+str(e))
        
    return render(request,'macs/keycard_set_active.htm',macs_default_context({'keycard':keycard}))

@permission_required('macs.change_member')
def keycard_unassign(request, key_id):
    "unassign a keycard from a member"
    keycard = get_object_or_404(Keycard,pk=key_id)
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == int(key_id):
                member = keycard.member
                keycard.member = None
                keycard.save()
                _log_activity(request,keycard,'modify','unassigned keycard number [%s] from member [%s]'%(keycard.number,member.get_full_name()))
                return redirect(keycard)
            else:
                raise ValueError('validation error')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to unassign keycard -> "+str(e))
        
    return render(request,'macs/keycard_unassign.htm',macs_default_context({'keycard':keycard}))
    
    
class KeycardCsvUploadForm(djforms.Form):
    "form for uploading keycards from CSV"
    csv_file = djforms.FileField()
    
@permission_required('macs.change_member')
def keycard_csv_upload(request):
    "upload a batch of keycards in a CSV file"
    
    if request.method == 'POST':
        form = KeycardCsvUploadForm(request.POST,request.FILES)
        if form.is_valid():
            try:
                # read the CSV file, use a StringIO object to buffer the
                # data since the django UploadedFile object does not have
                # a readline() method which is needed by the csv module
                fp = StringIO(request.FILES['csv_file'].read())
                warnings = []
                new_card_count = 0
                reader = csv_module.reader(fp)
                for i,row in enumerate(reader):
                    if i == 0:
                        continue
                    
                    if len(row) < 2:
                        warnings.append('Row %d: less than 2 columns'%(i+1))
                        continue
                    
                    try:
                        keycard = Keycard(number=row[0].lower(),comment=row[1],active=True)
                        keycard.save()           
                        _log_activity(request,keycard,'create','number = [%s], id = [%d] (imported from CSV)'%(keycard.number,keycard.id))
                        new_card_count += 1
                    except Exception as e:
                        warnings.append('Row %d: could not create keycard -> %s'%(i+1,e))
                
                if len(warnings):
                    messages.add_message(request,messages.WARNING,'<br />'.join(warnings))
                messages.add_message(request,messages.SUCCESS,'Added %d new keycards'%new_card_count)
                
                return redirect('macs.views.keycard_manage_all')
                
            except Exception as e:
                messages.add_message(request,messages.ERROR,'Unable to parse CSV file -> '+str(e))
    else:
        form = KeycardCsvUploadForm()

    return render(request,'macs/keycard_csv_upload.htm',macs_default_context({'form':form}))

class KeycardBatchCreateForm(djforms.Form):
    """form for batch creation of keycards CSV
    
    need to use a manual form rather than a ModelForm since
    the validation of ModelForm does not work correctly when
    used as part of a formset (Django bug)
    """
    
    number = djforms.CharField(max_length=64)
    comment = djforms.CharField(max_length=255,required=False)
    
    def clean_number(self):
        value = self.cleaned_data['number']
        keycard_number_ok(value)
        return value.lower()
    
@permission_required('macs.change_member')
def keycard_batch_create(request):
    "create a batch of keycards manually"
    KeycardBatchCreateFormSet = djforms.formset_factory(KeycardBatchCreateForm,extra=5)
    
    if request.method == 'POST':
        formset = KeycardBatchCreateFormSet(request.POST)
        if formset.is_valid():
            new_card_count = 0
            warnings = []
            for form in formset:
                data = form.cleaned_data
                if 'number' in data:
                    try:
                        keycard = Keycard(number=data['number'],comment=data['comment'])
                        keycard.save()
                        _log_activity(request,keycard,'create','number = [%s], id = [%d]'%(keycard.number,keycard.id))
                        new_card_count += 1
                    except Exception as e:
                        warnings.append("could not create keycard -> {}".format(e))
                    
            if len(warnings):
                messages.add_message(request,messages.WARNING,'<br />'.join(warnings))
            if new_card_count:
                messages.add_message(request,messages.SUCCESS,'Added %d new keycards'%new_card_count)
                        
            return redirect('macs.views.keycard_manage_all')
    else:
        formset = KeycardBatchCreateFormSet()

    return render(request,'macs/keycard_batch_create.htm',macs_default_context({'formset':formset}))

@permission_required('macs.change_member')
def keycard_set_lockout_card(request, key_id):
    "set a keycard to be a special lockout card"
    keycard = get_object_or_404(Keycard,pk=key_id)
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == int(key_id):
                if keycard.member:
                    raise ValueError("keycard is assigned to a member")
                keycard.lockout_card = True
                keycard.save()
                _log_activity(request,keycard,'modify','number = [%s], lockout_card = [True]'%keycard.number)
                return redirect(keycard)
            else:
                raise ValueError('validation error')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to convert keycard to a 'lockout' card -> {}".format(e))
        
    return render(request,'macs/keycard_set_lockout.htm',macs_default_context({'keycard':keycard}))

@permission_required('macs.change_member')
def keycard_unset_lockout_card(request, key_id):
    "remove special lockout functionality from a keycard"
    keycard = get_object_or_404(Keycard,pk=key_id)
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == int(key_id):
                keycard.lockout_card = False
                keycard.save()
                _log_activity(request,keycard,'modify','number = [%s], lockout_card = [False]'%keycard.number)
                return redirect(keycard)
            else:
                raise ValueError('validation error')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to remove 'lockout' functionality form card -> {}".format(e))
        
    return render(request,'macs/keycard_unset_lockout.htm',macs_default_context({'keycard':keycard}))

    
###########################################################################################################
###########################################################################################################
#######                     resource creation and modification views                                ####### 
###########################################################################################################
###########################################################################################################

class CreateEditResourceForm(djforms.ModelForm):
    "form for creating and editing member data"
    
    class Meta:
        model = Resource
        fields = ['name','description','secret','cost_per_hour','admin_url']
    

@permission_required('macs.change_resource')
def resource_create(request):
    "create a new resource (door, tool, etc)"
        
    if request.method == 'POST':
        form = CreateEditResourceForm(request.POST,request.FILES)    
        if form.is_valid():
            # create the resource
            resource = form.save()
            _log_activity(request,resource,'create','name = [%s]'%resource.name)
            return redirect(resource)
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')        
    
    else:
        # create an un-bound form when the request is not a POST
        form = CreateEditResourceForm()
        
    context = macs_default_context({'form': form})
    return render(request,'macs/resource_create.htm',context)
    
@login_required
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
            if form.has_changed():
                resource = form.save()
                _log_activity(request,resource,'modify','changed fields: %s'%(', '.join(form.changed_data)))
            return redirect(resource)
        else:
            messages.add_message(request,messages.ERROR,'Validation failed. Please check form fields for errors.')
            
    else:
        form = CreateEditResourceForm(instance=resource)
    
    context['form'] = form
    return render(request,'macs/resource_edit.htm',context)

@permission_required('macs.change_resource')
def resource_unlock(request, rsc_id):
    "unlock a resource"
    resource = get_object_or_404(Resource,pk=rsc_id)
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == int(rsc_id):
                resource.locked = False
                resource.save()
                _log_activity(request,resource,'modify','name = [%s], locked = [False]'%resource.name)
                return redirect(resource)
            else:
                raise ValueError('validation error')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to unlock resource -> {}".format(e))
        
    return render(request,'macs/resource_unlock.htm',macs_default_context({'resource':resource}))

@permission_required('macs.change_resource')
def resource_lock(request, rsc_id):
    "unlock a resource"
    resource = get_object_or_404(Resource,pk=rsc_id)
    if request.method == 'POST':
        try:
            req_id = int(request.POST['id'])
            if req_id == int(rsc_id):
                resource.locked = True
                resource.save()
                _log_activity(request,resource,'modify','name = [%s], locked = [True]'%resource.name)
                return redirect(resource)
            else:
                raise ValueError('validation error')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to lock resource -> {}".format(e))
        
    return render(request,'macs/resource_lock.htm',macs_default_context({'resource':resource}))
    
    
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
    page = request.GET.get('page','1')
    try:
        p = pager.page(int(page))
    except Exception:
        p = pager.page(1)
        
    context = macs_default_context({'page':p})
    return render(request,'macs/report_access_log.htm',context)
    
@permission_required('macs.change_member')
def report_activity_log(request):
    "view the admin activity log"
    ninety_days_ago = timezone.now() - datetime.timedelta(days=90)
    qs = ActivityLog.objects.filter(timestamp__gt=ninety_days_ago)
    
    if request.GET.get('csv',''):
        # CSV file download
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="activity-log-'+datetime.datetime.now().strftime('%Y%m%d')+'.csv"'
        writer = csv_module.writer(response)
        writer.writerow(['Timestamp','User','Action','Model','Model ID','Details'])
        for log in qs:
            fields = [log.timestamp.strftime('%Y/%m/%d %H:%M:%S'),log.user.get_full_name(),log.action,log.model_name,str(log.model_id),log.details]
            writer.writerow([f.encode('cp1252','replace') for f in fields])      
        return response    
    
    # normal response
    pager = Paginator(qs,100)
    page = request.GET.get('page','1')
    try:
        p = pager.page(int(page))
    except Exception:
        p = pager.page(1)
        
    context = macs_default_context({'page':p})
    return render(request,'macs/report_activity_log.htm',context)
    
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
    
@login_required
def schedule_show(request):
    "show the current schedule"
    today = datetime.date.today()
    yesterday = today - datetime.timedelta(days=1)
    future_window = today + datetime.timedelta(days=91)
    
    context = macs_default_context({
        'daily_schedule':DailySchedule.objects.all(),
        'upcoming_exceptions':ScheduleException.objects.filter(date__gt=yesterday).filter(date__lt=future_window),
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
            _log_activity(request,schedule,'create','day = [%d], start = [%s], end = [%s]'%(schedule.day,schedule.start_time.strftime('%H:%M:%S'),schedule.end_time.strftime('%H:%M:%S')))
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
            if form.has_changed():
                schedule = form.save()
                _log_activity(request,schedule,'modify','changed fields: %s'%(', '.join(form.changed_data)))
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
                _log_activity(request,schedule,'delete')
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
            _log_activity(request,schedule,'create','date = [%s], start = [%s], end = [%s], open=[%s]'%(schedule.date.strftime('%Y/%m/%d'),schedule.start_time.strftime('%H:%M:%S'),schedule.end_time.strftime('%H:%M:%S'),schedule.open))
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
            if form.has_changed():
                schedule = form.save()
                _log_activity(request,schedule,'modify','changed fields: %s'%(', '.join(form.changed_data)))
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
                _log_activity(request,schedule,'delete')
                schedule.delete()
                return redirect('macs.views.schedule_show')
            else:
                raise ValueError('Validation error.')
        except Exception as e:
            messages.add_message(request,messages.ERROR,"Unable to delete -> "+str(e))

    context = macs_default_context({'schedule':schedule})
    return render(request,'macs/schedule_remove_exception.htm',context)
    
    
