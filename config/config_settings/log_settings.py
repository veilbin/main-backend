import os
from pathlib import Path
from . import BASE_DIR

# define directories for applications to store log files
authentication_dir = os.path.join(BASE_DIR, 'logs', 'authentication_logs')
users_dir = os.path.join(BASE_DIR, 'logs', 'users_logs')
file_dir = os.path.join(BASE_DIR, 'logs', 'file_logs')
general_dir = os.path.join(BASE_DIR, 'logs', 'general_logs')

# create directories or skip if they already exists
os.makedirs(authentication_dir, exist_ok=True)
os.makedirs(users_dir, exist_ok=True)
os.makedirs(file_dir, exist_ok=True)
os.makedirs(general_dir, exist_ok=True)

# configure logging
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {asctime} {message}',
            'style': '{',
        },
    },
    'handlers': {
        # log settings for authentication app
        'authentication_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(authentication_dir, 'authentication_logs.log'),
            'formatter': 'verbose',
        },
        # log settings for users app
        'users_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(users_dir, 'users_logs.log'),
            'formatter': 'verbose',
        },
        # log settings for file app
        'files_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(file_dir, 'files_log.log'),
            'formatter': 'verbose',
        },
        # general log settings for django app
        'general_file': {
            'level': 'DEBUG',
            'class': 'logging.FileHandler',
            'filename': os.path.join(general_dir, 'general_logs.log'),
            'formatter': 'verbose',
        },
    },
    'loggers': {
        'general': {
            'handlers': ['general_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'authentication': {
            'handlers': ['authentication_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'users': {
          'handlers': ['users_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
        'files': {
          'handlers': ['files_file'],
            'level': 'DEBUG',
            'propagate': False,
        },
    },
}