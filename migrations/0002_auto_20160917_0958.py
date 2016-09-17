# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models, migrations


class Migration(migrations.Migration):

    dependencies = [
        ('macs', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='DailySchedule',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('day', models.IntegerField(help_text=b'day of the week', choices=[(b'1', b'Monday'), (b'2', b'Tuesday'), (b'3', b'Wednesday'), (b'4', b'Thursday'), (b'5', b'Friday'), (b'6', b'Saturday'), (b'7', b'Sunday')])),
                ('start_time', models.TimeField(help_text=b'start of time period when Makerspace is open')),
                ('end_time', models.TimeField(help_text=b'end of time period when Makerspace is open')),
            ],
            options={
                'ordering': ('day', 'start_time'),
            },
            bases=(models.Model,),
        ),
        migrations.CreateModel(
            name='ScheduleException',
            fields=[
                ('id', models.AutoField(verbose_name='ID', serialize=False, auto_created=True, primary_key=True)),
                ('date', models.DateField(help_text=b'schedule exception date')),
                ('start_time', models.TimeField(help_text=b'start of time period for the exception')),
                ('end_time', models.TimeField(help_text=b'end of time period for the exception')),
                ('open', models.BooleanField(default=False, help_text=b'Makerspace is open during the exception period')),
                ('comment', models.CharField(help_text=b'optional comment', max_length=255, blank=True)),
            ],
            options={
                'ordering': ('date', 'start_time'),
            },
            bases=(models.Model,),
        ),
        migrations.AlterField(
            model_name='member',
            name='membership_type',
            field=models.CharField(help_text=b'Type of membership', max_length=64, choices=[(b'individual', b'Individual'), (b'family', b'Family'), (b'administrative', b'Administrative'), (b'teacher', b'Teacher')]),
        ),
    ]
