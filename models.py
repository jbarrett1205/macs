from django.db import models
from django.contrib.auth.models import User
from django.conf import settings
from django.core.exceptions import ValidationError
try:
    from django.urls import reverse
except ImportError:
    from django.core.urlresolvers import reverse
import re

MEMBERSHIP_TYPES = [
    ('individual','Individual'),
    ('family','Family'),
    ('administrative','Administrative'),
    ('teacher','Teacher'),
]

class Member(User):
    """Core membership info for a Makerspace user
    
    This model is derived from the Django built-in User model which handles
    the default authentication in the Django infrastructure.
    """
    
    membership_type = models.CharField(max_length=64,choices=MEMBERSHIP_TYPES,help_text="Type of membership")
    expires = models.DateField()
    resources = models.ManyToManyField('Resource',through='ResourceAllowed',through_fields=('member','resource'))
    comments = models.TextField(blank=True)
    # try to match the amherst rec account records to the makerspace account
    billing_id = models.CharField(max_length=255,blank=True,help_text="ID to help with future direct link to Amherst Rec billing")
        
    def __unicode__(self):
        return u'%s %s'%(self.first_name,self.last_name)
            
    def get_absolute_url(self):
        return reverse('macs.views.member_view',args=[str(self.id)])
        
    def get_keycard_list(self):
        "get a list of keycards by number"
        r = []
        for card in self.keycard_set.all():
            r.append(card.number)
        return r

    class Meta:
        ordering = ('last_name','first_name')
        
def keycard_number_ok( value ):
    "keycard number validator"
    if not re.match(r'^[0123456789abcdef]{8,}$',value, re.I):
        raise ValidationError('keycard ID must be a hexadecimal string, 8 characters or more')
    
        
class Keycard(models.Model):
    "keycard assigned to a member and used for resource access"
    number = models.CharField(max_length=64,unique=True,help_text="Keycard ID String (hexadecimal)",validators=[keycard_number_ok])
    member = models.ForeignKey(Member,null=True,blank=True,on_delete=models.SET_NULL,help_text="Member assigned to this card")
    active = models.BooleanField(default=True,blank=True,help_text="keycard is active")
    comment = models.CharField(max_length=128,help_text="optional comment")
    
    def __unicode__(self):
        return self.number + ' (' + self.comment.strip() + ')'
    
    def get_absolute_url(self):
        return reverse('macs.views.keycard_manage',args=[str(self.id)])  
        
    class Meta:
        ordering = ('active','number')
        
        
class Resource(models.Model):
    """Resources defined by the makerspace
    
    anything that can be accessed with a makerspace keycard
    (including the door) is a resource
    """
    name = models.CharField(max_length=64,unique=True,help_text="resource name")
    description = models.CharField(max_length=255,blank=True,help_text="additional information about the resource")
    secret = models.CharField(max_length=32,blank=True,help_text="resource secret key")
    cost_per_hour = models.FloatField(blank=True,default=0.0,help_text="cost per hour of use")
        
    def __unicode__(self):
        return u'%d: %s'%(self.id,self.name)
    
    def get_absolute_url(self):
        return reverse('macs.views.resource_view',args=[str(self.id)])  
    
    class Meta:
        ordering = ('name',)
    

class ResourceAllowed(models.Model):
    """Intermediate model that links Resource objects to Member objects
    
    This allows storage of specific Member-to-Resource attributes
    """
    member = models.ForeignKey(Member,on_delete=models.CASCADE)
    resource = models.ForeignKey(Resource,on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    trainer = models.CharField(max_length=64,help_text="trainer name")
    comment = models.CharField(max_length=255,blank=True,help_text="optional comment")

    
class ResourceAccessLog(models.Model):
    """logging mechanism for recording resource access transactions"""
    keycard = models.CharField(max_length=64)
    member = models.ForeignKey(Member,null=True,on_delete=models.SET_NULL)
    resource = models.ForeignKey(Resource,on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    allowed = models.BooleanField(blank=True,default=False)
    reason_code = models.IntegerField()
            
    class Meta:
        ordering = ('-timestamp',)
            
class ResourceUsage(models.Model):
    """record usage of resources that support this feature"""
    member = models.ForeignKey(Member,on_delete=models.CASCADE)
    resource = models.ForeignKey(Resource,on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    minutes = models.FloatField(help_text="minutes of usage")
    
class ActivityLog(models.Model):
    """log activity in MACS - this is for auditing purposes"""
    user = models.ForeignKey(User,on_delete=models.CASCADE)
    timestamp = models.DateTimeField(auto_now_add=True)
    model_name = models.CharField(max_length=128)
    model_id = models.IntegerField()
    action = models.CharField(max_length=32)
    details = models.TextField(blank=True)

class DailySchedule(models.Model):
    """store the daily schedule for the makerspace to be open
    
    multiple instances of this can be created for each week day, allowing
    multiple time periods during the day when the space is open
    """
    WEEKDAYS_ISO_FMT = [
        (1,'Monday'),
        (2,'Tuesday'),
        (3,'Wednesday'),
        (4,'Thursday'),
        (5,'Friday'),
        (6,'Saturday'),
        (7,'Sunday'),
    ]
    day = models.IntegerField(choices=WEEKDAYS_ISO_FMT,help_text="day of the week")
    start_time = models.TimeField(help_text="start of time period when Makerspace is open")
    end_time = models.TimeField(help_text="end of time period when Makerspace is open")
    
    class Meta:
        ordering = ('day','start_time')
        
    
class ScheduleException(models.Model):
    """Store exceptions to the normal daily schedule
    
    Each exception is valid for a single calendar date and can be
    set as the Makerspace being either open or closed for the time
    window given
    
    In the code that processes the open/closed schedule, exceptions
    will take precedence over the daily schedule.
    """
    date = models.DateField(help_text="schedule exception date")
    start_time = models.TimeField(help_text="start of time period for the exception")
    end_time = models.TimeField(help_text="end of time period for the exception")
    open = models.BooleanField(blank=True,default=False,help_text="Makerspace is open during the exception period")
    comment = models.CharField(max_length=255,blank=True,help_text="optional comment")
    
    class Meta:
        ordering = ('date','start_time')
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
    
            