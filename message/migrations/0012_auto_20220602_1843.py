# Generated by Django 3.2.10 on 2022-06-02 17:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message', '0011_auto_20220602_1713'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='short_id',
            field=models.CharField(default='BDHO0C4Q9', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='room',
            name='room_id',
            field=models.CharField(default='A2NASEGNZ', max_length=255, unique=True),
        ),
    ]
