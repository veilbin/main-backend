import os
from pathlib import Path
from dotenv import load_dotenv


# define base directory 
BASE_DIR = Path(__file__).resolve().parent.parent.parent
# load env 
load_dotenv(dotenv_path=BASE_DIR/'.env')
# load secret key 
SECRET_KEY = os.getenv('SECRET_KEY')