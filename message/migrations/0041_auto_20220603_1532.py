# Generated by Django 3.2.10 on 2022-06-03 14:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message', '0040_auto_20220603_1529'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='short_id',
            field=models.CharField(default='KR6PKN3K2', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='room',
            name='room_id',
            field=models.CharField(default='305Y6RJWJ', max_length=255, unique=True),
        ),
    ]
