from django.http import Http404
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import permissions, status
from django.contrib.auth import get_user_model
import logging

from util.api_response import ResponseUtils
from .models import DeletionSchedule
from authentication.serializers import UserSerializer

User = get_user_model()
logger = logging.getLogger('admin')

# get all users 
class GetUsers(APIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = UserSerializer

    # get queryset 
    def get_queryset(self):
        return User.objects.all()
    
    # get request 
    def get(self, request, *args, **kwargs):
        try:
            user = self.get_queryset()
            serializer = self.serializer_class(user, many=True if isinstance(user, list) else False)
            return ResponseUtils.success_response(
                message = "users fetched",
                data= serializer.data,
                status_code= status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f": Error fetching all users: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # create user 
    def post(self, request, *args, **kwargs):
        try:
            serializer = UserSerializer(data=request.data)
            if serializer.is_valid():
                serializer.save()
                logger.info(f": New user created by {request.user}")
                return ResponseUtils.success_response(
                    message= "User created",
                    status_code= status.HTTP_201_CREATED
                )
            return ResponseUtils.error_response(
                message= "Invalid data format",
                details= serializer.errors,
                status_code= status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f": Error creating new user: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "Unable to create user",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )


# get users details 
class GetUserDetails(APIView):
    permission_classes = [permissions.IsAdminUser]
    serializer_class = UserSerializer

    def get_object(self, pk):
        try:
            return User.objects.filter(pk=pk).first()
        
        except User.DoesNotExist():
            return Http404("User does not exist")
        
        except Exception as e:
            logger.error(f": Error fetching users details: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 
    
    # get user 
    def get(self, request, pk, *args, **kwargs):
        try:
            user = self.get_object(pk)
            serializer = self.serializer_class(user)
            logger.info(f": User {request.user} accessed {user}'s data")
            return ResponseUtils.success_response(
                message= "User data fetched",
                data= serializer.data,
                status_code= status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f": Error fetching user data: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # update user using put method 
    def put(self, request, pk, *args, **kwargs):
        try:
            user = self.get_object(pk)
            serializer = self.serializer_class(user, data=request.data, partial=True, context={'request':request})
            if serializer.is_valid():
                serializer.save()
                logger.info(f": user {request.user} updated {user}'s details")
                return ResponseUtils.error_response(
                    message= "User details updated",
                    status_code= status.HTTP_200_OK
                )
            return ResponseUtils.error_response(
                message= "Invalid data format",
                status_code= status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f": Error updating user data: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # update user using patch method 
    def patch(self, request, pk, *args, **kwargs):
        try:
            user = self.get_object(pk)
            serializer = self.serializer_class(user, data=request.data, context={'request':request})
            if serializer.is_valid():
                serializer.save()
                logger.info(f": user {request.user} updated {user}'s details")
                return ResponseUtils.error_response(
                    message= "User details updated",
                    status_code= status.HTTP_200_OK
                )
            return ResponseUtils.error_response(
                message= "Invalid data format",
                status_code= status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f": Error updating user data: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    
    def delete(self, request, pk, *args, **kwargs):
        try:
            user = self.get_object(pk)
            logger.info(f": user {request.user} is making a delete request for {user}'s account")
            user.delete()
            return ResponseUtils.success_response(
                message= "User account deleted",
                status_code= status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f": Error deleting user account: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
