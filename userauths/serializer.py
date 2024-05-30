from django.contrib.auth.password_validation import validate_password
from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth import get_user_model

from userauths.models import Profile, User

class MyTokenObtainPairSerializer(TokenObtainPairSerializer):
    @classmethod
    def get_token(cls, user):
        token = super().get_token(user)

        token['full_name'] = user.full_name
        token['email'] = user.email
        token['username'] = user.username
        try:
            token['vendor_id'] = user.vendor.id
        except:
            token['vendor_id'] = 0

        return token

class RegisterSerializer(serializers.ModelSerializer):
    #password = serializers.CharField(write_only=True, required=True, validators=[validate_password])
    #password2 = serializers.CharField(write_only=True, required=True)

    class Meta:
        model = User
        fields = ['full_name', 'email', 'phone', 'password']
        #fields = ('__all__')

        #def validate(self, attrs):
            #if attrs['password'] != attrs['password2']:
                #raise serializers.ValidationError({"password": "Password does not match"})
            #return attrs
        def create_user(self, email, password, **extra_fields):
            """
            Create and save a user with the given email and password.
            """
            if not email:
                raise ValueError(_("The Email must be set"))
            email = self.normalize_email(email)
            user = self.model(email=email, **extra_fields)
            user.set_password(password)
            user.save()
            return user

        def create(self, validated_data):
            validated_data.pop('password2', None)
            user = User.objects.create(
                full_name=validated_data['full_name'],
                email=validated_data['email'],
                phone=validated_data['phone'],
            )

            email_user, mobile = user.email.split("@")
            user.username = email_user
            user.set_password(validated_data['password'])
            user.save()

            return user

class UserSerializer(serializers.ModelSerializer):
    """Serializer for the user object"""

    class Meta:
        model = get_user_model()
        fields = ['full_name', 'email', 'password', 'phone']
        extra_kwargs = {'password': {'write_only': True, 'min_length': 5}}

    def create(self, validated_data):
        """Create and return a user with encrypted password"""
        return get_user_model().objects.create_user(**validated_data)


class ProfileSerializer(serializers.ModelSerializer):
     #user = UserSerializer()
     class Meta:
         model = Profile
         fields = "__all__"

     def to_representation(self, instance):
         response = super().to_representation(instance)
         response['user'] = UserSerializer(instance.user).date
         return response
