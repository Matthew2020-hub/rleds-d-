# Generated by Django 3.2.10 on 2022-06-03 14:13

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('message', '0036_auto_20220603_1459'),
    ]

    operations = [
        migrations.AlterField(
            model_name='message',
            name='short_id',
            field=models.CharField(default='D3DUPZY80', max_length=255, unique=True),
        ),
        migrations.AlterField(
            model_name='room',
            name='room_id',
            field=models.CharField(default='ZE3PL5C92', max_length=255, unique=True),
        ),
    ]
