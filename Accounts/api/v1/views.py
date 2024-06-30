from rest_framework import generics
from .serializer import (
    RegistrationSerializer,
    CustomAuthTokenSerializer,
    CustomTokenObtainPairSerializer,
    ChangePasswordSerializer,
    ProfileSerializer,
)
from rest_framework import status
from rest_framework.response import Response
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token
from rest_framework.views import APIView
from rest_framework.permissions import (
    IsAuthenticated,
    
)
from Accounts.models import User , Profile
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework_simplejwt.tokens import RefreshToken
import jwt
from django.conf import settings
from jwt import ExpiredSignatureError, InvalidAudienceError
from django.contrib.auth import get_user_model
from django.shortcuts import get_object_or_404


User = get_user_model()


class Registration(generics.GenericAPIView):
    serializer_class = RegistrationSerializer

    def post(self, request, *args, **kwargs):
        serializer = RegistrationSerializer(data=request.data)

        if serializer.is_valid():
            serializer.save()
            email = serializer.validated_data["email"]
            data = {"email": email}
            return Response(data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def get_tokens_for_user(self, user):
        refresh = RefreshToken.for_user(user)
        return str(refresh.access_token)


class CustomObtainAuth(ObtainAuthToken):
    """Give More information when Create User"""

    serializer_class = CustomAuthTokenSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data["user"]
        token, created = Token.objects.get_or_create(user=user)
        return Response(
            {"token": token.key, "user_id": user.pk, "email": user.email}
        )


class CustomDiscard(APIView):
    """Delete Token"""

    permission_classes = [IsAuthenticated]

    def post(self, request):
        request.user.auth_token.delete()
        print(request)
        return Response(status=status.HTTP_204_NO_CONTENT)


class CustomTokenObtainPairView(TokenObtainPairView):
    serializer_class = CustomTokenObtainPairSerializer


class ChangePassword(generics.GenericAPIView):

    model = User
    permission_classes = [IsAuthenticated]
    serializer_class = ChangePasswordSerializer

    def get_object(self, required=None):
        obj = self.request.user
        return obj

    def put(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():

            """Check old password"""

            if not self.object.check_password(
                serializer.data.get("old_password")
            ):
                return Response(
                    {"old_password": ["Wrong password."]},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            """ set_password also hashes the password that the user will get """
            self.object.set_password(serializer.data.get("new_password"))
            self.object.save()

            return Response(
                {"details": "Password changed successfully"},
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class Profile(generics.RetrieveUpdateAPIView):

    serializer_class = ProfileSerializer
    queryset = Profile.objects.all()

    def get_object(self):
        queryset = self.get_queryset()
        obj = get_object_or_404(queryset, user=self.request.user)
        return obj


class Activation(APIView):

    def get(self, request, token, *args, **kwargs):

        try:
            token = jwt.decode(
                token, settings.SECRET_KEY, algorithms=["HS256"]
            )
            user_id = token.get("user_id")
        except ExpiredSignatureError:
            return Response(
                {"detail": "This Token Signature"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        except InvalidAudienceError:
            return Response(
                {"detail": "This Token is Not Valid"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        user_obj = User.objects.get(pk=user_id)
        if user_obj.is_verified:
            return Response(
                {"detail": "Your account have has already been verified"}
            )

        user_obj.is_verified = True
        user_obj.is_active = True
        user_obj.save()
        return Response(
            {
                "detail": "Your account have has Verified and Activation successfully"
            }
        )
        
        
