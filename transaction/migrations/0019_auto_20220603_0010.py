# Generated by Django 3.2.10 on 2022-06-02 23:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0018_auto_20220603_0008'),
    ]

    operations = [
        migrations.AlterField(
            model_name='paymenthistory',
            name='short_id',
            field=models.CharField(default='N0LTEW11I', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='rooms',
            name='room_id',
            field=models.CharField(default='GO1VZPPB3', max_length=255, unique=True),
        ),
    ]
