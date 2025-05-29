from rest_framework import permissions, status
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth import get_user_model
from django.db import transaction
from django.utils import timezone
from django.http import Http404
from datetime import time, timedelta
import logging

from util.api_response import ResponseUtils
from .serializers import FileSeriailizer
from .models import File

User = get_user_model()
logger = logging.getLogger("files")


# create/upload file
class FileView(APIView):
    permission_classes = [permissions.IsAuthenticated,]
    serializer_class = FileSeriailizer

    # queryset
    def get_queryset(self):
        user = self.request.user
        try:
            return File.objects.filter(owner=user)
        except File.DoesNotExist:
            raise Http404("File does not exist")
        except Exception as e:
            logger.error(f": An unexpected error occurred while fetching user files: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message="An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    # get all files by user 
    def get(self, request, *args, **kwargs):
        try:
            file = self.get_queryset()
            serializer = self.serializer_class(file, many=True if isinstance(file, list) else False)
            logger.info(f": user {request.user} fetched all files data")
            return ResponseUtils.success_response(
                message= "File(s) fetched",
                data= serializer.data,
                status_code= status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f": An unexpected error occurred while fecting {request.user} files: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # create / upload file 
    def post(self, request, *args, **kwargs):
        serializer = FileSeriailizer(request.data)
        if serializer.is_valid():
            filename = serializer.validated_data['filename']
            file = serializer.validated_data['file']
            expiration = serializer.validated_data['expiration']
            
            try:
                created_file = File.objects.create(
                    filename = filename,
                    file = file,
                    owner = request.user,
                    expiration = expiration
                )
                created_file.save()
                logger.info(f": User {request.user} uploaded a new file")
                return ResponseUtils.success_response(
                    message= "File uploaded",
                    status_code= status.HTTP_200_OK
                )
            except Exception as e:
                logger.error(f": Error uploading new file: {e}", exc_info=True)
                return ResponseUtils.error_response(
                    message= "An unexpected error occurred",
                    status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
                )



