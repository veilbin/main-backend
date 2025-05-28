import os
from . import BASE_DIR, SECRET_KEY
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv(dotenv_path=BASE_DIR / '.env')

SECRET_KEY = SECRET_KEY

REST_FRAMEWORK =  {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        os.getenv('REST_FRAMEWORK_DEFAULT_AUTH'),
    )
}

# Jwt Config
SIMPLE_JWT = {
	"ACCESS_TOKEN_LIFETIME": timedelta(days=int(os.getenv('ACCESS_TOKEN_LIFETIME'))),
	"REFRESH_TOKEN_LIFETIME": timedelta(days=int(os.getenv('REFRESH_TOKEN_LIFETIME'))),
	"ROTATE_REFRESH_TOKENS": True,
	"BLACKLIST_AFTER_ROTATION": True,
	"UPDATE_LAST_LOGIN": True,

	"ALGORITHM": os.getenv('JWT_ALGORITHM'),
	"SIGNING_KEY": SECRET_KEY,
    'VERIFYING_KEY': None,
    'AUDIENCE': None,
    'ISSUER': None,
    'JWK_URL': None,
    'LEEWAY': 0,

    'AUTH_HEADER_TYPES': ('Bearer',),
    'AUTH_HEADER_NAME': 'HTTP_AUTHORIZATION',
    'USER_ID_FIELD': 'id',
    'USER_ID_CLAIM': 'user_id',
    'USER_AUTHENTICATION_RULE': 'rest_framework_simplejwt.authentication.default_user_authentication_rule',

    'AUTH_TOKEN_CLASSES': ('rest_framework_simplejwt.tokens.AccessToken',),
    'TOKEN_TYPE_CLAIM': 'token_type',
    'TOKEN_USER_CLASS': 'rest_framework_simplejwt.models.TokenUser',

    'JTI_CLAIM': 'jti',

    "SLIDING_TOKEN_REFRESH_EXP_CLAIM": "refresh_exp",
    "SLIDING_TOKEN_LIFETIME": timedelta(minutes=int(os.getenv('SLIDING_TOKEN_LIFETIME'))),
    "SLIDING_TOKEN_REFRESH_LIFETIME": timedelta(days=int(os.getenv('SLIDING_TOKEN_REFRESH_LIFETIME'))),

}