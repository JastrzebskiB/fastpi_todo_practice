def get_jwt_service() -> "JWTService":
    from .services import JWTService
    return JWTService()


def get_user_service() -> "UserService":
    from .services import UserService
    return UserService()


def get_organization_service() -> "OrganizationService":
    from .services import OrganizationService
    return OrganizationService()
