"""Deterministic patch: replace wildcard gateway CORS with explicit origins."""
PATCH_MARKER = "# CYBERGUARDIAN_PATCH: explicit_cors_origins_v1"


def patch_source(source: str) -> str:
    if PATCH_MARKER in source:
        return source
    old = '''app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT"],
    allow_headers=["*"],
)'''
    new = '''# CYBERGUARDIAN_PATCH: explicit_cors_origins_v1
_cors_origins = [
    origin.strip()
    for origin in os.getenv(
        "CG_ALLOWED_ORIGINS",
        "http://127.0.0.1:3000,http://localhost:3000",
    ).split(",")
    if origin.strip()
]
if not _cors_origins or "*" in _cors_origins:
    raise RuntimeError("CG_ALLOWED_ORIGINS must contain explicit origins; wildcard CORS is forbidden")
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Tenant-ID"],
)'''
    if source.count(old) != 1:
        raise ValueError("wildcard CORS middleware anchor missing or ambiguous")
    return source.replace(old, new, 1)
