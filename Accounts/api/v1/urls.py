from django.urls import path
from . import views


from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView


urlpatterns = [
    path("", views.Profile.as_view(), name="profile"),
    # Registration
    path("registration/", views.Registration.as_view(), name="registration"),
    # Login Token
    # path('token/login' , ObtainAuthToken.as_view() , name='token-login'),
    path(
        "token/login/", views.CustomObtainAuth.as_view(), name="token-login"
    ),
    path("token/logout/", views.CustomDiscard.as_view(), name="token-logout"),
    # activation
    path(
        "activation/confirm/<str:token>",
        views.Activation.as_view(),
        name="activation",
    ),
    # Change password
    path(
        "change-password/",
        views.ChangePassword.as_view(),
        name="change-password",
    ),
    path(
        "jwt/create/",
        views.CustomTokenObtainPairView.as_view(),
        name="custom-jwt-create",
    ),
    path("jwt/refresh/", TokenRefreshView.as_view(), name="jwt_refresh"),
    path("jwt/verify/", TokenVerifyView.as_view(), name="jwt_verify"),
]
