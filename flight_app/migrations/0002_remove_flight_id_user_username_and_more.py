# Generated by Django 4.1.7 on 2023-02-27 14:41

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('flight_app', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='flight',
            name='id',
        ),
        migrations.AddField(
            model_name='user',
            name='username',
            field=models.CharField(max_length=50, null=True, unique=True),
        ),
        migrations.AlterField(
            model_name='flight',
            name='flight_number',
            field=models.CharField(max_length=20, primary_key=True, serialize=False, unique=True),
        ),
        migrations.AlterField(
            model_name='user',
            name='email',
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]
