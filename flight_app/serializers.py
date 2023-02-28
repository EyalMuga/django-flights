from .models import Flight, Order, User
import django.contrib.auth.password_validation as validators
from rest_framework import serializers, status, viewsets, generics
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.models import User, Group, Permission, AbstractUser, BaseUserManager, UserManager, AbstractBaseUser
from rest_framework.response import Response
from django.contrib.auth import authenticate, login, logout, get_user_model, update_session_auth_hash
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated,IsAdminUser




class RegistrationSeralizer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    class Meta:
        model = User
        fields = ['email', 'username', 'password','first_name','last_name','is_staff']

    def validate(self, args):
        email = args.get('email', None)
        username = args.get('username', None)
        if User.objects.filter(email=email).exists():
            raise serializers.ValidationError('Email is already in use')
        if User.objects.filter(username=username).exists():
            raise serializers.ValidationError('Username is already in use')
        
        return super().validate(args)
    
    
    def create(self, validated_data):
        return User.objects.create_user(**validated_data)
    
    def update(self, instance, validated_data):
        password = validated_data.remove('password', None)
        for (key, value) in validated_data.items():
            setattr(instance, key, value)
        if password is not None:
            instance.set_password(password)
        instance.save()
        return instance

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['email', 'username', 'password','first_name','last_name','is_staff']

class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'


class FlightSerializer(serializers.ModelSerializer):
    class Meta:
        model = Flight
        fields = '__all__'

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=255, min_length=3)
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    username = serializers.CharField(max_length=255, min_length=3, read_only=True)
    tokens = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['email', 'password', 'username', 'tokens']
        
    def get_tokens(self, obj):
        user = User.objects.get(email=obj['email'])
        refresh = RefreshToken.for_user(user)
        return {
            'refresh': str(refresh),
            'access': str(refresh.access_token),
        }
    
    def validate(self, attrs):
        email = attrs.get('email', None)
        password = attrs.get('password', None)
        user = authenticate(email=email, password=password)
        if not user:
            raise AuthenticationFailed('Invalid credentials, try again')
        if not user.is_active:
            raise AuthenticationFailed('Account disabled, contact admin')
        if not user.is_verified:
            raise AuthenticationFailed('Email is not verified')
        return {
            'email': user.email,
            'username': user.username,
            'tokens': user.tokens
        }
        return super().validate(attrs)

class OrderUserIdViewSet(viewsets.ModelViewSet):
    serializer_class = OrderSerializer
    permission_classes = [IsAuthenticated]
    def get_queryset(self):
        return Order.objects.filter(User.id==self.request.user.id)


# return total price 
class BookFlightSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = ['flight', 'num_seats']

        def validate(self, args):
            flight = args.get('flight', None)
            num_seats = args.get('num_seats', None)
            if flight.seats_left < num_seats:
                raise serializers.ValidationError('Not enough seats left')
            return super().validate(args)
        
        def create(self, validated_data):
            return Order.objects.create(**validated_data)
        
