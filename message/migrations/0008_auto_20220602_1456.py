# Generated by Django 3.2.10 on 2022-06-02 13:56

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message', '0007_auto_20220531_1552'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='short_id',
            field=models.CharField(default='J4TD4TQIU', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='room',
            name='room_id',
            field=models.CharField(default='EJJXPU9F1', max_length=255, unique=True),
        ),
    ]
