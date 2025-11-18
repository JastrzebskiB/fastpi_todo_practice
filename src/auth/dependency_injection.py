# Separate file is necessary due to "cross-pollination" of OrganizationService and UserService - 
# having these functions in services.py means that nothing works :D

def get_user_service():
    from .services import UserService
    return UserService


def get_organization_service():
    from .services import OrganizationService
    return OrganizationService
