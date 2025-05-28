import os
from . import BASE_DIR
from dotenv import load_dotenv

load_dotenv(dotenv_path=BASE_DIR / '.env')

# Application database
DATABASES = {
    'default': {
        'ENGINE': os.getenv('DATABASE_ENGINE'),
        'NAME': BASE_DIR / os.getenv('DATABASE_NAME'),
    }
}

# celery config
CELERY_BROKER_URL = os.getenv('CELERY_BROKER_URL')
CELERY_ACCEPT_CONTENT = [os.getenv('CELERY_ACCEPT_CONTENT')]
CELERY_TASK_SERIALIZER = os.getenv('CELERY_TASK_SERIALIZER')
CELERY_TASK_PREFIX = os.getenv('CELERY_TASK_PREFIX')

# store celery tasks result to django database
CELERY_RESULT_BACKEND = os.getenv('CELERY_RESULT_BACKEND')
CELERY_RESULT_EXTENDED = True