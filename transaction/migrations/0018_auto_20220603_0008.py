# Generated by Django 3.2.10 on 2022-06-02 23:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0017_auto_20220603_0006'),
    ]

    operations = [
        migrations.AlterField(
            model_name='paymenthistory',
            name='short_id',
            field=models.CharField(default='JS7DGI9LT', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='rooms',
            name='room_id',
            field=models.CharField(default='VLX8V9GGW', max_length=255, unique=True),
        ),
    ]
