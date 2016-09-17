# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations
import django.db.models.deletion
from django.conf import settings


class Migration(migrations.Migration):

    dependencies = [
        ('auth', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ActivityLog',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('model_name', models.CharField(max_length=128)),
                ('model_id', models.IntegerField()),
                ('action', models.CharField(max_length=32)),
                ('details', models.TextField(blank=True)),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='Member',
            fields=[
                ('user_ptr', models.OneToOneField(parent_link=True, auto_created=True, primary_key=True, serialize=False, to=settings.AUTH_USER_MODEL)),
                ('keycard', models.CharField(help_text=b'Keycard ID String (hexadecimal)', max_length=64, blank=True)),
                ('membership_type', models.CharField(help_text=b'Type of membership', max_length=64, choices=[(b'individual', b'Individual'), (b'family', b'Family'), (b'administrative', b'Administrative')])),
                ('expires', models.DateField()),
                ('comments', models.TextField(blank=True)),
                ('billing_id', models.CharField(help_text=b'ID to help with future direct link to Amherst Rec billing', max_length=255, blank=True)),
            ],
            options={
                'ordering': ('last_name', 'first_name'),
            },
            bases=('auth.user',),
        ),
        migrations.CreateModel(
            name='Resource',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('name', models.CharField(help_text=b'resource name', unique=True, max_length=64)),
                ('description', models.CharField(help_text=b'additional information about the resource', max_length=255, blank=True)),
                ('secret', models.CharField(help_text=b'resource secret key', max_length=32, blank=True)),
                ('cost_per_hour', models.FloatField(default=0.0, help_text=b'cost per hour of use', blank=True)),
            ],
            options={
                'ordering': ('name',),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ResourceAccessLog',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('keycard', models.CharField(max_length=64)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('allowed', models.BooleanField(default=False)),
                ('reason_code', models.IntegerField()),
                ('member', models.ForeignKey(on_delete=django.db.models.deletion.SET_NULL, to='macs.Member', null=True)),
                ('resource', models.ForeignKey(to='macs.Resource')),
            ],
            options={
                'ordering': ('-timestamp',),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ResourceAllowed',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('trainer', models.CharField(help_text=b'trainer name', max_length=64)),
                ('comment', models.CharField(help_text=b'optional comment', max_length=255, blank=True)),
                ('member', models.ForeignKey(to='macs.Member')),
                ('resource', models.ForeignKey(to='macs.Resource')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ResourceUsage',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('timestamp', models.DateTimeField(auto_now_add=True)),
                ('minutes', models.FloatField(help_text=b'minutes of usage')),
                ('member', models.ForeignKey(to='macs.Member')),
                ('resource', models.ForeignKey(to='macs.Resource')),
            ],
            options={
            },
            bases=(models.Model,),
        ),
        migrations.AddField(
            model_name='member',
            name='resources',
            field=models.ManyToManyField(to='macs.Resource', through='macs.ResourceAllowed'),
            preserve_default=True,
        ),
        migrations.AddField(
            model_name='activitylog',
            name='user',
            field=models.ForeignKey(to=settings.AUTH_USER_MODEL),
            preserve_default=True,
        ),
    ]
