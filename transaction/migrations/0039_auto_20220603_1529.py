# Generated by Django 3.2.10 on 2022-06-03 14:29

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0038_auto_20220603_1514'),
    ]

    operations = [
        migrations.AlterField(
            model_name='paymenthistory',
            name='short_id',
            field=models.CharField(default='I5TD28CNX', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='rooms',
            name='room_id',
            field=models.CharField(default='796SH68PY', max_length=255, unique=True),
        ),
    ]
