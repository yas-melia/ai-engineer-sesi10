from fastapi import FastAPI, HTTPException, Header, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from typing import Optional, Dict
from datetime import date, datetime, timedelta, timezone
from math import ceil
import hmac
import secrets
import logging

import jwt as pyjwt
from pydantic_settings import BaseSettings, SettingsConfigDict

from db import (
    count_articles_by_source,
    search_articles,
    get_department_detail,
    get_attrition_risk_profile,
    get_article_by_id,
    get_attrition_summary,
)

log = logging.getLogger(__name__)

class Settings(BaseSettings):
    database_url: str
    student_name: str
    internal_api_key: str
    jwt_secret: str
    jwt_expiry_minutes: int = 30
    client_id: str
    client_secret: str

    model_config = SettingsConfigDict(
        env_file=".env", case_sensitive=False, extra="ignore"
    )

settings = Settings()

app = FastAPI(
    title="News & HR Analytics API",
    description=(
        "Homework Sesi 11: Dua data pipeline, satu API.\n\n"
    ),
    version="1.0",
)
security_scheme = HTTPBearer(auto_error=False)

class Article(BaseModel):
    """Model untuk satu artikel dari tabel articles."""
    id: int
    title: str
    url: str
    source: str
    content: Optional[str] = None
    published_at: Optional[datetime] = None
    scraped_at: Optional[datetime] = None


# TODO 26: Lengkapi Pydantic model untuk ArticleStats
#
# Endpoint /articles/stats akan return JSON seperti ini:
# {
#     "total_articles": 512,
#     "by_source": {"bbc": 50, "nytimes": 30, "books.toscrape": 200, ...}
# }
#
# Hint: total_articles bertipe int, by_source bertipe Dict[str, int]
class ArticleStats(BaseModel):
    total_articles: int
    by_source: Dict[str, int]


class ArticleSearchResponse(BaseModel):
    data: list[Article]
    page: int
    per_page: int
    total_items: int
    total_pages: int


class DepartmentTopEarner(BaseModel):
    EmployeeNumber: int
    JobRole: str
    MonthlyIncome: int


class DepartmentDetail(BaseModel):
    department: str
    total_employees: int
    attrition_count: int
    attrition_rate: float
    avg_income: float | None
    min_income: int | None
    max_income: int | None
    top_earners: list[DepartmentTopEarner]


class TokenRequest(BaseModel):
    """Request body untuk POST /token."""
    client_id: str
    client_secret: str


class TokenResponse(BaseModel):
    """Response dari POST /token."""
    access_token: str
    token_type: str = "bearer"
    expires_in: int


# TODO 27: Lengkapi Pydantic model untuk AttritionSummary
#
# Endpoint /attrition/summary akan return JSON seperti ini:
# {
#     "total_employees": 1470,
#     "attrition_yes": 237,
#     "attrition_no": 1233,
#     "attrition_rate": 0.1612
# }
#
# Hint: semua int kecuali attrition_rate yang float
class AttritionSummary(BaseModel):
    total_employees: int
    attrition_yes: int
    attrition_no: int
    attrition_rate: float


# ==================================================================
# Authentication Helpers
#
# API ini support 2 metode autentikasi:
#   1. API Key — kirim header X-API-Key
#   2. JWT Bearer — POST /token dulu, lalu kirim header Authorization
#
# Keduanya bisa dipakai di endpoint yang sama.
# ==================================================================

def create_access_token(client_id: str) -> str:
    """Buat JWT token dengan expiry."""
    # TODO 28: Buat JWT payload dan encode
    #
    # Hint:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": client_id,                                          # subject = siapa pemilik token
        "iat": now,                                                # issued at
        "exp": now + timedelta(minutes=settings.jwt_expiry_minutes), # expiry
        "jti": secrets.token_hex(16),                              # unique token ID
    }
    return pyjwt.encode(payload, settings.jwt_secret, algorithm="HS256")


def verify_jwt_token(token: str) -> dict:
    """Decode dan validasi JWT token. Raise HTTPException jika invalid."""
    try:
        return pyjwt.decode(token, settings.jwt_secret, algorithms=["HS256"])
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token sudah expired")
    except pyjwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token tidak valid")


def verify_api_key(x_api_key: Optional[str] = Header(None)):
    """Cek API key dari header X-API-Key."""
    # TODO 29: Validasi API key
    #
    # Logika:
    #   1. Jika x_api_key is None → return None (tidak ada key, bukan error)
    #   2. Jika key cocok dengan settings.internal_api_key → return {"auth_method": "api_key"}
    #   3. Jika key TIDAK cocok → raise HTTPException(status_code=401)
    #
    # Hint: Gunakan hmac.compare_digest(a, b) untuk perbandingan aman
    #       (mencegah timing attack, lebih secure dari == biasa)
    if x_api_key is None:
            return None
    if hmac.compare_digest(x_api_key, settings.internal_api_key):
        return {"auth_method": "api_key"}
    raise HTTPException(status_code=401, detail="API Key tidak valid")


def get_current_client(
    api_key_result=Depends(verify_api_key),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme),
):
    """
    Dependency utama — terima API Key ATAU Bearer token.
    FastAPI akan inject hasil verify_api_key dan credentials otomatis.
    """
    # TODO 30: Gabungkan kedua metode auth
    #
    # Logika:
    #   1. Jika api_key_result is not None → return api_key_result (sudah valid dari verify_api_key)
    #   2. Jika credentials is not None → decode JWT token, return hasilnya
    #      payload = verify_jwt_token(credentials.credentials)
    #      return {"auth_method": "bearer", "client_id": payload["sub"]}
    #   3. Jika keduanya None → raise HTTPException 401 "Authentication required"
    #
    if api_key_result is not None:
            return api_key_result
    if credentials is not None:
        payload = verify_jwt_token(credentials.credentials)
        return {"auth_method": "bearer", "client_id": payload["sub"]}
    raise HTTPException(status_code=401, detail="Authentication Required. Gunakan API Key atau JWT")

# ==================================================================
# PUBLIC ENDPOINTS — tanpa auth
# ==================================================================
@app.get("/", tags=["Public"])
def read_root():
    return {
        "message": "News & HR Analytics API — Session 11",
        "student": settings.student_name,
        "paths": {
            "etl_articles": "/articles/search",
            "elt_attrition": "/attrition/summary",
            "docs": "/docs",
        },
    }

@app.get("/health", tags=["Public"])
def health_check():
    return {"status": "ok", "timestamp": datetime.now(timezone.utc).isoformat()}

# ==================================================================
# AUTH ENDPOINT
# ==================================================================
@app.post("/token", response_model=TokenResponse, tags=["Auth"])
def login_for_token(req: TokenRequest):
    """Exchange client_id + client_secret untuk JWT access token."""
    # TODO 31: Validasi credentials dan return token
    #
    # Langkah:
    #   1. Compare req.client_id dengan settings.client_id (hmac.compare_digest)
    #   2. Compare req.client_secret dengan settings.client_secret
    #   3. Jika SALAH → raise HTTPException(status_code=401, detail="Invalid client credentials")
    #   4. Jika BENAR → buat token dan return TokenResponse
    #
    # Hint:
    valid_id = hmac.compare_digest(req.client_id, settings.client_id)
    valid_secret = hmac.compare_digest(req.client_secret, settings. client_secret)
    if not(valid_id and valid_secret):
        raise HTTPException(status_code=401, detail="Invalid Client Credentials")
    token = create_access_token(req.client_id)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=settings.jwt_expiry_minutes * 60,  # convert menit ke detik
    )

@app.get("/articles/search", response_model=ArticleSearchResponse, tags=["Articles (ETL)"])
def article_search(
    source: str | None = None,
    title: str | None = None,
    date_from: str | None = Query(None, pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"),
    date_to: str | None = Query(None, pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$"),
    page: int = Query(1, ge=1),
    per_page: int = Query(10, ge=1, le=50),
    auth=Depends(get_current_client),
):
    """Cari artikel dengan filter opsional dan pagination."""
    try:
        start = date.fromisoformat(date_from) if date_from is not None else None
        end = date.fromisoformat(date_to) if date_to is not None else None
    except ValueError:
        raise HTTPException(status_code=422, detail="Gunakan tanggal kalender yang valid (YYYY-MM-DD).")

    if start is not None and end is not None and start > end:
        raise HTTPException(status_code=422, detail="date_from tidak boleh setelah date_to.")

    articles, total = search_articles(source, title, start, end, page, per_page)
    return ArticleSearchResponse(
        data=articles,
        page=page,
        per_page=per_page,
        total_items=total,
        total_pages=ceil(total / per_page),
    )


@app.get("/articles/stats", response_model=ArticleStats, tags=["Articles (ETL)"])
def article_stats(auth=Depends(get_current_client)):
    by_source = count_articles_by_source()
    return ArticleStats(total_articles=sum(by_source.values()), by_source=by_source)


@app.get("/articles/{article_id}", response_model=Article, tags=["Articles (ETL)"])
def get_single_article(
    article_id: int,
    auth=Depends(get_current_client),
):
    """Get single article by database ID."""
    article = get_article_by_id(article_id)
    if not article:
        raise HTTPException(status_code=404, detail="Article not found")
    return article


@app.get("/attrition/department/{dept_name}", response_model=DepartmentDetail, tags=["Attrition (ELT)"])
def attrition_department_detail(dept_name: str, auth=Depends(get_current_client)):
    """Tampilkan statistik attrition dan tiga gaji tertinggi dalam satu department."""
    detail = get_department_detail(dept_name)
    if detail is None:
        raise HTTPException(status_code=404, detail="Department not found")
    return detail


@app.get("/attrition/risk-profile", response_model=list[dict], tags=["Attrition (ELT)"])
def attrition_risk_profile(
    limit: int = Query(20, ge=1, le=100),
    auth=Depends(get_current_client),
):
    """Tampilkan karyawan yang memenuhi ketiga indikator risiko attrition."""
    return get_attrition_risk_profile(limit)


@app.get("/attrition/summary", response_model=AttritionSummary, tags=["Attrition (ELT)"])
def attrition_summary(auth=Depends(get_current_client)):
    """Overall attrition stats."""
    # TODO 34: Panggil get_attrition_summary() dan return hasilnya
    return get_attrition_summary()
