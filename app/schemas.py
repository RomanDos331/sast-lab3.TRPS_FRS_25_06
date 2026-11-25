from datetime import datetime
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator

class ProjectCreate(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    repository_url: str | None = Field(default=None, max_length=500)
    source_code: str = Field(min_length=1)

    @field_validator("name")
    @classmethod
    def name_not_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("Название проекта не должно быть пустым")
        return value.strip()

class ProjectUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    repository_url: str | None = Field(default=None, max_length=500)
    source_code: str | None = Field(default=None, min_length=1)

class ProjectRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    name: str
    repository_url: str | None
    created_at: datetime

class ScanCreate(BaseModel):
    project_id: int = Field(gt=0)

class ScanRead(BaseModel):
    id: int
    project_id: int
    status: str
    created_at: datetime
    findings_count: int

class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    rule_id: str
    title: str
    description: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    status: str

class GateDecisionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    passed: bool
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    message: str
    max_critical: int
    max_high: int

class ReportCreate(BaseModel):
    format: Literal["json", "html", "sarif"] = "json"

class ReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    scan_id: int
    format: str
    content: str
    created_at: datetime
