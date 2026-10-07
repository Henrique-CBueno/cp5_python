from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CvssAssessment(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False)
    version: Literal["2.0", "3.0", "3.1", "4.0"]
    score: float = Field(ge=0, le=10)
    severity: Literal["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL", "UNKNOWN"]
    vector: str = Field(min_length=1)
    source: str = Field(min_length=1)
    type: Literal["Primary", "Secondary"]
    data: dict

    @property
    def precedence(self):
        return (
            -float(self.version),
            self.type != "Primary",
            self.source != "nvd@nist.gov",
            self.source,
        )
