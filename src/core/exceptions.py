from fastapi import HTTPException, status


AuthenticationFailedException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
AuthorizationFailedException = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="You do not have the permission to perform this action",
    headers={"WWW-Authenticate": "Bearer"},
)
BadJWTException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="JWT malformed or missing",
    headers={"WWW-Authenticate": "Bearer"},
)
ExpiredJWTException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Authentication token has expired",
    headers={"WWW-Authenticate": "Bearer"},
)
# TODO: Consider if those and ValidationException for not founds are needed
UserNotFound = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
OrganizationNotFound = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="Organization not found",
)
OrganizationAccessRequestNotFound = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="OrganizationAccessRequest not found",
)
BoardNotFound = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Board not found")
ColumnNotFound = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Column not found")
TaskNotFound = HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Task not found")


class ValidationException(HTTPException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=detail
        )
