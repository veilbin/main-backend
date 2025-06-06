from django.http import Http404
from django.shortcuts import get_object_or_404, render
from django.db import transaction
from rest_framework.views import APIView
from rest_framework import permissions, status
from django.contrib.auth import get_user_model
import logging

from util.api_response import ResponseUtils
from .models import DeletionSchedule, Profile
from .serializers import ProfileSerializer

User = get_user_model()
logger = logging.getLogger('admin')

# get profile 
class ProfileView(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileSerializer

    # get queryset 
    def get_queryset(self):
        try:
            user = self.request.user
            return get_object_or_404(
                Profile.objects.filter(  
                    user=user,
                )
            )
        except Exception as e:
            logger.error(f": Error fecthing profile of {user}: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    # get request 
    def get(self, request, *args, **kwargs):
        try:
            profile = self.get_queryset()
            serializer = self.serializer_class(profile, many=True if isinstance(profile, list) else False)
            return ResponseUtils.success_response(
                message = "profile fetched",
                data= serializer.data,
                status_code= status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f": Error gettng the profile of {request.user}: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # # create profile 
    # def post(self, request, *args, **kwargs):
    #     try:
    #         serializer = ProfileSerializer(data=request.data)
    #         if serializer.is_valid():
    #             serializer.save()
    #             logger.info(f": New profile created by {request.user}")
    #             return ResponseUtils.success_response(
    #                 message= "Profile created",
    #                 status_code= status.HTTP_201_CREATED
    #             )
    #         return ResponseUtils.error_response(
    #             message= "Invalid data format",
    #             details= serializer.errors,
    #             status_code= status.HTTP_400_BAD_REQUEST
    #         )
    #     except Exception as e:
    #         logger.error(f": Error creating new profile {request.user}: {e}", exc_info=True)
    #         return ResponseUtils.error_response(
    #             message= "Unable to create user",
    #             status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
    #         )


# get profile details 
class ProfileDetails(APIView):
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ProfileSerializer

    def get_object(self, pk):
        try:
            return Profile.objects.filter(pk=pk).first()
        
        except Profile.DoesNotExist():
            return Http404("Profile does not exist")
        
        except Exception as e:
            logger.error(f": Error fetching profile details: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            ) 
    
    # get profile 
    def get(self, request, pk, *args, **kwargs):
        try:
            profile = self.get_object(pk)
            serializer = self.serializer_class(profile)
            logger.info(f": User {request.user} accessed {profile}'s data")
            return ResponseUtils.success_response(
                message= "Profile data fetched",
                data= serializer.data,
                status_code= status.HTTP_200_OK
            )
        except Exception as e:
            logger.error(f": Error fetching profile data: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # update profile using put method 
    def put(self, request, pk, *args, **kwargs):
        try:
            profile = self.get_object(pk)
            serializer = self.serializer_class(profile, data=request.data, partial=True, context={'request':request})
            if serializer.is_valid():
                serializer.save()
                logger.info(f": user {request.user} updated {profile}'s details")
                return ResponseUtils.error_response(
                    message= "Profile details updated",
                    status_code= status.HTTP_200_OK
                )
            return ResponseUtils.error_response(
                message= "Invalid data format",
                status_code= status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            logger.error(f": Error updating profile data: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
        
    # update profile using patch method 
    def patch(self, request, pk, *args, **kwargs):
        try:
            profile = self.get_object(pk)
            serializer = self.serializer_class(profile, data=request.data, context={'request':request})
            if serializer.is_valid():
                serializer.save()
                logger.info(f": user {request.user} updated {profile}'s details")
                return ResponseUtils.error_response(
                    message= "Profile details updated",
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
        
    
    # def delete(self, request, pk, *args, **kwargs):
    #     try:
    #         profile = self.get_object(pk)
    #         logger.info(f": user {request.user} is making a delete request for {profile}'s account")
    #         profile.delete()
    #         return ResponseUtils.success_response(
    #             message= "Profile account deleted",
    #             status_code= status.HTTP_200_OK
    #         )
        
    #     except Exception as e:
    #         logger.error(f": Error deleting user account: {e}", exc_info=True)
    #         return ResponseUtils.error_response(
    #             message= "An unexpected error occurred",
    #             status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
    #         )

# lock user account view 
class LockAccount(APIView):
    permission_classes = [permissions.IsAdminUser]

    def post(self, request, pk, *args, **Kwargs):
        try:
            user = User.objects.get(pk=pk)
            if not user:
                return ResponseUtils.error_response(
                    message= "User does not exist",
                    status_code= status.HTTP_404_NOT_FOUND
                )
            user.is_locked = True 
            user.save()
            logger.info(f": User {request.user} locked {user}'s account")
            return ResponseUtils.success_response(
                message= "Account locked successfully",
                status_code= status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f": Error locking user account: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )

# disable user account view 
class DisableAccount(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, pk, *args, **Kwargs):
        try:
            user = User.objects.get(pk=pk, user=request.user)
            if not user:
                return ResponseUtils.error_response(
                    message= "User does not exist",
                    status_code= status.HTTP_404_NOT_FOUND
                )
            user.is_disabled = True 
            user.save()
            
            # add disabled account to 'to_be_deleted model'
            to_be_deleted = DeletionSchedule.objects.create(user=user)
            to_be_deleted.save()

            logger.info(f": User {request.user} disabled {user}'s account")
            return ResponseUtils.success_response(
                message= "Account disabled successfully",
                status_code= status.HTTP_200_OK
            )
        
        except Exception as e:
            logger.error(f": Error disabling user account: {e}", exc_info=True)
            return ResponseUtils.error_response(
                message= "An unexpected error occurred",
                status_code= status.HTTP_500_INTERNAL_SERVER_ERROR
            )
     