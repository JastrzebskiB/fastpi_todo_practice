from pydantic import BaseModel, UUID4


# Board
class CreateBoardPayload(BaseModel):
    organization_id: UUID4
    name: str
    add_default_columns: bool = True

    use_columns_from_board_id: UUID4 | None = None


class BoardResponseFlat(BaseModel):
    id: UUID4
    organization_id: UUID4
    name: str


class BoardResponse(BaseModel):
    id: UUID4
    organization_id: UUID4
    name: str

    columns: list["ColumnResponseFlat"]


class BoardResponseFullDetails(BaseModel):
    id: UUID4
    organization_id: UUID4
    name: str

    columns: list["ColumnResponse"]


# Column
class CreateColumnPayload(BaseModel):
    board_id: UUID4
    name: str
    order: int


class ColumnResponseFlat(BaseModel):
    id: UUID4
    board_id: UUID4
    name: str
    order: int


class ColumnResponse(BaseModel):
    id: UUID4
    board_id: UUID4
    name: str
    order: int

    tasks: list["TaskResponseFlat"]


# Task
class TaskResponseFlat(BaseModel):
    id: UUID4
    column_id: UUID4
    assigned_to: UUID4 | None
    name: str
    order: int
