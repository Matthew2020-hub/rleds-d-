# Generated by Django 3.2.10 on 2022-06-03 14:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0042_auto_20220603_1533'),
    ]

    operations = [
        migrations.AlterField(
            model_name='paymenthistory',
            name='short_id',
            field=models.CharField(default='0IYAT3QBL', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='rooms',
            name='room_id',
            field=models.CharField(default='ZNUE57SUL', max_length=255, unique=True),
        ),
    ]
