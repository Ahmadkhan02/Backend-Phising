from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from account.serializers import SendPasswordResetEmailSerializer, UserChangePasswordSerializer, UserLoginSerializer, UserPasswordResetSerializer, UserProfileSerializer, UserRegistrationSerializer, UserSearchSerializer
from django.contrib.auth import authenticate
from account.renderers import UserRenderer
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated
from .apps import WebappConfig
from .ml_utils import term_mapping, URL_Converter
from .models import UserSearch

# Generate Token Manually
def get_tokens_for_user(user):
  refresh = RefreshToken.for_user(user)
  return {
      'refresh': str(refresh),
      'access': str(refresh.access_token),
  }

class UserRegistrationView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserRegistrationSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    user = serializer.save()
    token = get_tokens_for_user(user)
    return Response({'token':token, 'msg':'Registration Successful'}, status=status.HTTP_201_CREATED)

class UserLoginView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = UserLoginSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    email = serializer.data.get('email')
    password = serializer.data.get('password')
    user = authenticate(email=email, password=password)
    if user is not None:
      token = get_tokens_for_user(user)
      return Response({'token':token, 'msg':'Login Success'}, status=status.HTTP_200_OK)
    else:
      return Response({'errors':{'non_field_errors':['Email or Password is not Valid']}}, status=status.HTTP_404_NOT_FOUND)

class UserProfileView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def get(self, request, format=None):
    serializer = UserProfileSerializer(request.user)
    return Response(serializer.data, status=status.HTTP_200_OK)

class UserChangePasswordView(APIView):
  renderer_classes = [UserRenderer]
  permission_classes = [IsAuthenticated]
  def post(self, request, format=None):
    serializer = UserChangePasswordSerializer(data=request.data, context={'user':request.user})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Changed Successfully'}, status=status.HTTP_200_OK)

class SendPasswordResetEmailView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, format=None):
    serializer = SendPasswordResetEmailSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset link send. Please check your Email'}, status=status.HTTP_200_OK)

class UserPasswordResetView(APIView):
  renderer_classes = [UserRenderer]
  def post(self, request, uid, token, format=None):
    serializer = UserPasswordResetSerializer(data=request.data, context={'uid':uid, 'token':token})
    serializer.is_valid(raise_exception=True)
    return Response({'msg':'Password Reset Successfully'}, status=status.HTTP_200_OK)

#make callmodel such that auth is needed for it 
#also add a get method to callmodel, with count and skip parameters in query. pass it to Usersearch method
class CallModel(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        """
        Handle POST requests to predict phishing URLs.

        Args:
            urls : can be a list or a single string of url

        Returns:
            Response: A JSON response with the prediction result.

        This view function can handle two cases:
        1. If the "url" parameter in the request data is a string, it treats it as a single URL and predicts
           whether it is benign or phishing. The response contains the URL and the corresponding prediction label.

        2. If the "url" parameter is a list of strings, it processes each URL in the list and predicts their
           respective labels. The response is a list of dictionaries, each containing the URL and its prediction label.

        If the input is neither a string nor a list, the view returns an error response with a 400 Bad Request status code.
        """
        if request.method == 'POST':
            urls_raw = request.data.get("urls")
            user_id = request.user.id
            if isinstance(urls_raw, list):
                # If urls is a list, process each URL
                urls = URL_Converter(urls_raw)
                results_of_urls = WebappConfig.predictor.predict(urls)
                res = [{'url': url, 'label': term_mapping[label]} for url, label in zip(urls, results_of_urls)]

                 # Save each URL prediction result to the UserSearch model
                for url, label in zip(urls_raw, results_of_urls):
                  user_search = UserSearch.create_user_search(user_id, urls_raw, results_of_urls[0])

            elif isinstance(urls_raw, str):
                # If urls is a single string, process it as a single URL
                urls = URL_Converter([urls_raw])  # Convert the string to a list
                results_of_urls = WebappConfig.predictor.predict(urls)
                res = [{'url': urls_raw, 'label': term_mapping[results_of_urls[0]]}]

                #store in db
                user_search = UserSearch.create_user_search(user_id, urls_raw, results_of_urls[0])

            else:
                return Response({'error': 'Invalid input. The "url" parameter should be a string or a list of strings.'}, status=status.HTTP_400_BAD_REQUEST)
            
            return Response({'response': res})

    def get(self, request, format=None):
        '''get for getting user models, pass the count reqired in each call and skip required in each call
        '''
        user_id = request.user.id
        count = request.query_params.get("count") or 10 
        skip = request.query_params.get("skip") or 0
        
        if count is None or skip is None:
            return Response(
                {'error': 'count and skip query parameters are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        user_searches = UserSearch.get_user_searches(user_id, int(count), int(skip))
        serializer = UserSearchSerializer(user_searches, many=True)

        return Response(serializer.data, status=status.HTTP_200_OK)