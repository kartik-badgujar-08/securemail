from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from app.api.pcap import router as pcap_router
from app.database import init_db
from app.services.tshark_parser import TSharkParser


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables if PostgreSQL is available
    init_db()
    tshark_ok = TSharkParser.is_available()
    print(f"[*] Engine Status: TShark available = {tshark_ok} (Scapy fallback ready)")
    yield


app = FastAPI(
    title="Email Protocol TLS Security & Risk Analysis API",
    description="Passive PCAP analysis engine for SMTP/IMAP/POP3 encryption audit and risk scoring.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(pcap_router)


@app.exception_handler(Exception)
async def global_exception_handler(request, exc: Exception):
    import traceback
    error_str = str(exc)
    if "ConnectionTimeout" in error_str or "connection timeout expired" in error_str or "OperationalError" in type(exc).__name__:
        return JSONResponse(
            status_code=503,
            content={
                "detail": "PostgreSQL database offline or unreachable. Please verify PostgreSQL is running at localhost:5432 or check the DATABASE_URL in backend/.env."
            },
        )
    return JSONResponse(
        status_code=500,
        content={"detail": f"Internal Server Error: {error_str}"},
    )


@app.get("/api/health", tags=["System Health"])
def health_check():
    from app.database import db_type
    return {
        "status": "online",
        "engine": "tshark" if TSharkParser.is_available() else "scapy",
        "tshark_installed": TSharkParser.is_available(),
        "database": db_type,
    }
