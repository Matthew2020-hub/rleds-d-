# Generated by Django 3.2.10 on 2022-06-03 12:33

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('transaction', '0029_auto_20220603_1329'),
    ]

    operations = [
        migrations.AlterField(
            model_name='paymenthistory',
            name='short_id',
            field=models.CharField(default='2DKZD3823', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='rooms',
            name='room_id',
            field=models.CharField(default='AP0ZUNIZM', max_length=255, unique=True),
        ),
    ]
