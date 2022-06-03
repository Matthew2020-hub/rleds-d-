# Generated by Django 3.2.10 on 2022-06-03 01:14

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0020_auto_20220603_0157'),
    ]

    operations = [
        migrations.AlterField(
            model_name='paymenthistory',
            name='short_id',
            field=models.CharField(default='SFNYSTKHC', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='rooms',
            name='room_id',
            field=models.CharField(default='JM9EUD2EV', max_length=255, unique=True),
        ),
    ]
