from fastapi import HTTPException, status


AuthenticationFailedException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)
BadJWTException = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="JWT malformed or missing",
    headers={"WWW-Authenticate": "Bearer"},
)
NotTheOwner = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="You are not the owner of this Organization",
)
UserNotFound = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="User not found",
)
OrganizationNotFound = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="Organization not found",
)


class ValidationException(HTTPException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail
        )
