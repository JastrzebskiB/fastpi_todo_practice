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
