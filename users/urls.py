from django.urls import path
from .views import ProfileView, ProfileDetails, LockAccount, DisableAccount


urlpatterns = [
    path('profile/', ProfileView.as_view(), name='profiles'),
    path('profile/<int:pk>/', ProfileDetails.as_view(), name='profile_details'),
    path('lock_account/<int:pk>/', LockAccount.as_view(), name='lock_account'),
    path('disable_account/<int:pk>/', DisableAccount.as_view(), name='disable_account'),
]