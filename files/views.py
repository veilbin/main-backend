from django.shortcuts import get_object_or_404
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
            is_shareable = serializer.validated_data['is_shareable']
            expiration = serializer.validated_data['expiration']
            
            try:
                created_file = File.objects.create(
                    filename = filename,
                    file = file,
                    is_shareable = is_shareable,
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


# file details view 
class FileDetailView(APIView):
    permission_classes = [permissions.IsAuthenticated,]
    serializer_class = FileSeriailizer

    # get object 
    def get_object(self,pk):
        try:
            return File.objects.filter(pk=pk, owner=self.request.user)
        
        except File.DoesNotExist:
            return Http404("File does not exist")
        
        except Exception as e:
            logger.error(f": Error fetching user file details: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # get file 
    def get(self, request, pk, *args, **kwargs):
        try:
            file = self.get_object(pk)
            serializer = self.serializer_class(file)
            logger.Info(f": user {self.request.user} accessed file {file}")
            return ResponseUtils.success_response(
                message= "File fetched",
                data= serializer.data,
                status_code= status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f": Error fetching file data: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        

# file share view 
class FileShareView(APIView):
    permission_classes = [permissions.AllowAny,]
    serializer_class = FileSeriailizer

    # get file 
    def get(self, request, share_token):
        try:
            file = get_object_or_404(File, share_token=share_token, is_shareable=True)
            serializer = self.serializer_class(file, context={'request':request})
            return ResponseUtils.success_response(
                message= "File fetched",
                data= serializer.data,
                status_code= status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f"Error fetching file in FileShare View: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
