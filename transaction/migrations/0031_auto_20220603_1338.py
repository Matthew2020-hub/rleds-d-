# Generated by Django 3.2.10 on 2022-06-03 12:38

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0030_auto_20220603_1333'),
    ]

    operations = [
        migrations.AlterField(
            model_name='paymenthistory',
            name='short_id',
            field=models.CharField(default='O856H1FL1', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='rooms',
            name='room_id',
            field=models.CharField(default='5LEIRWQXK', max_length=255, unique=True),
        ),
    ]
