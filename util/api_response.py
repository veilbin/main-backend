from rest_framework.response import Response
from rest_framework import status

class ResponseUtils:
    @staticmethod
    # return standard success response
    def success_response(message, status_code, data=None, details=None):
        return Response({
            'result': 'success',
            'message': message,
            'data': data,
            'details':details},
            status=status_code
        )

    @staticmethod
    # return standardized error response
    def error_response(message, status_code, data=None, details=None):
        return Response({
            'result': 'error',
            'message': message,
            'data': data,
            'details': details},
            status=status_code
        )

    @staticmethod
    # return standardized error response
    def warning_response(message, status_code, data=None, details=None):
        return Response({
            'result': 'warning',
            'message': message,
            'data': data,
            'details': details},
            status=status_code
        )