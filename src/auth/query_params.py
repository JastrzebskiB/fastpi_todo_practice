from enum import StrEnum

from sqlalchemy import or_
from sqlalchemy.sql.elements import BinaryExpression, BooleanClauseList

from .models import OrganizationAccessRequest


class RequestAccessStatus(StrEnum):
    ALL = "all"
    PROCESSED = "processed"
    UNPROCESSED = "unprocessed"
    APPROVED = "approved"
    REJECTED = "rejected"

    @property
    def where_param(self) -> BinaryExpression | BooleanClauseList:
        if self == RequestAccessStatus.ALL:
            return or_(
                    OrganizationAccessRequest.approved == None,
                    OrganizationAccessRequest.approved == True,
                    OrganizationAccessRequest.approved == False,
                )
            
        elif self == RequestAccessStatus.PROCESSED:
            return or_(
                OrganizationAccessRequest.approved == True,
                OrganizationAccessRequest.approved == False,
            )
        elif self == RequestAccessStatus.UNPROCESSED:
            return OrganizationAccessRequest.approved == None
        elif self == RequestAccessStatus.APPROVED:
            return OrganizationAccessRequest.approved == True
        elif self == RequestAccessStatus.REJECTED:
            return OrganizationAccessRequest.approved == False
        
        raise VaueError(f"RequestAccessStatus {self=} had an unexpected value.")
