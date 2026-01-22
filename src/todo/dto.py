from pydantic import BaseModel, UUID4


class CreateBoardPayload(BaseModel):
    organization_id: UUID4
    name: str


class BoardResponseFlat(BaseModel):
    id: UUID4
    organization_id: UUID4
    name: str


class BoardResponse(BaseModel):
    id: UUID4
    organization_id: UUID4
    name: str

    # columns
    # tasks?
