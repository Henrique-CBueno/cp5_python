from pydantic import BaseModel, ConfigDict, EmailStr, Field


class Subscription(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    name: str = Field(min_length=1, max_length=100, pattern=r"^[^\r\n]+$")
    products: list[str] = Field(min_length=1, max_length=100)
    email: EmailStr | None = None
    changes: bool = False
    enabled: bool = True
