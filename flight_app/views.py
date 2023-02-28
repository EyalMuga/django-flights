
from rest_framework import generics, status, viewsets
from rest_framework.permissions import IsAuthenticated,IsAdminUser
from rest_framework.response import Response
from rest_framework.decorators import api_view, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view
from rest_framework.permissions import IsAuthenticated,IsAdminUser,AllowAny
from .models import *
from .serializers import *
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User


class RegisterView(generics.CreateAPIView):
    serializer_class = RegistrationSeralizer

    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if (serializer.is_valid()):
            serializer.save()
            return Response({"message": "User created successfully",
                                "data": serializer.data},
                                status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FlightViewSet(viewsets.ModelViewSet):
    queryset = Flight.objects.all()
    serializer_class = FlightSerializer

    def get_queryset(self):
        queryset = Flight.objects.all()
        origin = self.request.query_params.get('origin', None)
        destination = self.request.query_params.get('destination', None)
        if origin is not None:
            queryset = queryset.filter(origin_city=origin)
        if destination is not None:
            queryset = queryset.filter(destination_city=destination)
        return queryset
    
    def create(self, request, *args, **kwargs):
        if request.user.is_staff:
            return super().create(request, *args, **kwargs)
        else:
            return Response({"message": "You are not authorized to create a flight"},
                                status=status.HTTP_401_UNAUTHORIZED)
        
    def update(self, request, *args, **kwargs):
        if request.user.is_staff:
            return super().update(request, *args, **kwargs)
        else:
            return Response({"message": "You are not authorized to update a flight"},
                                status=status.HTTP_401_UNAUTHORIZED)
        
    def delete(self, request, *args, **kwargs):
        if request.user.is_staff:
            return super().delete(request, *args, **kwargs)
        else:
            return Response({"message": "You are not authorized to delete a flight"},
                                status=status.HTTP_401_UNAUTHORIZED)
        
# how to stay loged in and create flights
class LoginView(generics.CreateAPIView):
    serializer_class = LoginSerializer
    permission_classes = (AllowAny,)
    def post(self, request):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        password = serializer.validated_data['password']
        user = authenticate(email=email, password=password)
        if user is None:
            raise AuthenticationFailed('User not found')
        if not user.is_active:
            raise AuthenticationFailed('User is inactive')
        if not user.is_staff:
            raise AuthenticationFailed('User is not staff')
        login(request, user)
        return Response({"message": "User logged in successfully",
                            "data": serializer.data},
                            status=status.HTTP_200_OK)
        
    
    def logout(self, request):
        logout(request)
        return Response({"message": "User logged out successfully"},
                            status=status.HTTP_200_OK)
    
class BookFlightView(generics.CreateAPIView):
    serializer_class = BookFlightSerializer
    permission_classes = (IsAuthenticated,)
    def post(self, request, pk):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if (serializer.is_valid()):
            # update seats
            flight = Flight.objects.get(pk=pk)
            flight.seats_left -= int(serializer.validated_data['num_seats'])
            flight.save()
            serializer.save()
            return Response({"message": "Flight booked successfully",
                                "data": serializer.data},
                                status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

# add total price to the Order created
class BookedFlightView(generics.ListAPIView):
    serializer_class = OrderSerializer
    permission_classes = (IsAdminUser,)
    def get_queryset(self, *args, **kwargs):
        queryset = Order.objects.all()
        user = self.request.user
        queryset = queryset.filter(user=user)
        return queryset
    # get orders
    def get(self):
        serializer = self.serializer_class(self.get_queryset(), many=True)
        return Response({"message": "Booked flights",
                            "data": serializer.data},
                            status=status.HTTP_200_OK)
    # delete order
    def delete(self,pk):
        order = Order.objects.get(pk=pk)
        order.delete()
        return Response({"message": "Order deleted successfully"},
                            status=status.HTTP_200_OK)


class UpdateFlightView(generics.UpdateAPIView):
    serializer_class = BookFlightSerializer
    permission_classes = (IsAdminUser,)
    def put(self, request, pk):
        serializer = self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        if (serializer.is_valid()):
            serializer.save()
            return Response({"message": "Flight updated successfully",
                                "data": serializer.data},
                                status=status.HTTP_201_CREATED)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        



