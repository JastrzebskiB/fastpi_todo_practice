from typing import Any  

from pydantic import BaseModel, UUID4, model_validator

from ..core import exceptions


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
    name: str
    order: int
    is_terminal: bool = False


class PartialUpdateColumnPayload(BaseModel):
    name: str | None = None
    order: int | None = None
    is_terminal: bool | None = None

    @model_validator(mode="before")
    @classmethod
    def validate_at_least_one_field_present(cls, data: Any) -> Any:
        fields = ["name", "order", "is_terminal"]
        at_least_one_data_present = False
        for field in fields:
            if data.get(field) is not None:
                at_least_one_data_present = True
        
        if not at_least_one_data_present:
            raise exceptions.ValidationException(f"At least one of {fields} needs to be present")

        return data


class ColumnResponseFlat(BaseModel):
    id: UUID4
    board_id: UUID4
    name: str
    order: int
    is_terminal: bool


class ColumnResponse(BaseModel):
    id: UUID4
    board_id: UUID4
    name: str
    order: int
    is_terminal: bool

    tasks: list["TaskResponseFlat"]


# Task
class CreateTaskPayload(BaseModel):
    name: str
    description: str
    order: int
    assigned_to: UUID4 | None = None


class TaskResponseFlat(BaseModel):
    id: UUID4
    column_id: UUID4
    created_by: UUID4
    assigned_to: UUID4 | None
    name: str
    order: int
