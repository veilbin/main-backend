from __future__ import absolute_import, unicode_literals
from celery import Celery
import os

# configure settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.config_settings.settings')
# create celery app
app = Celery('config')

# configure celery
app.config_from_object('django.conf.settings', namespace='CELERY')
# auto discover task in installed apps
app.autodiscover_tasks()

@app.task(bind=True)
def debug_task(self):
    print(f"Request {self.request!r}")