# Generated by Django 3.2.10 on 2022-06-03 14:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message', '0042_auto_20220603_1533'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='short_id',
            field=models.CharField(default='IKAJ4YKMN', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='room',
            name='room_id',
            field=models.CharField(default='TONI5PLUZ', max_length=255, unique=True),
        ),
    ]
