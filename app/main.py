import io
import os
import zipfile
import logging
from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.responses import JSONResponse
from .analyzer import analyze_code
from .models import SecurityReport, ErrorResponse

# ── Logging ──────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="Code Security Agent",
    description=(
        "Upload a source file or a ZIP archive and get a structured JSON report "
        "of security vulnerabilities, powered by Llama 4 running on LM Studio / MLX."
    ),
    version="1.0.0",
)

# ── Constants ─────────────────────────────────────────────────────────────────
SUPPORTED_EXTENSIONS = {
    # Web / scripting
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".php",
    # Systems / compiled
    ".go", ".java", ".kt", ".scala", ".cs", ".cpp", ".c", ".h", ".hpp", ".rs", ".swift",
    # Shell
    ".sh", ".bash", ".zsh",
    # Config / IaC (often contain secrets or misconfigurations)
    ".yaml", ".yml", ".json", ".env", ".xml", ".toml",
    ".tf", ".hcl",  # Terraform / HCL
}

MAX_FILE_SIZE_BYTES  = int(os.getenv("MAX_FILE_SIZE_BYTES", str(200 * 1024)))   # 200 KB per file
MAX_FILES_PER_SCAN   = int(os.getenv("MAX_FILES_PER_SCAN", "30"))


# ── Helpers ───────────────────────────────────────────────────────────────────
def _is_supported(filename: str) -> bool:
    lower = filename.lower()
    return any(lower.endswith(ext) for ext in SUPPORTED_EXTENSIONS)


def _safe_decode(raw: bytes, filename: str) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        logger.warning(f"UTF-8 decode failed for {filename}, falling back to latin-1")
        return raw.decode("latin-1", errors="replace")


def _extract_files_from_zip(content: bytes) -> dict[str, str]:
    files: dict[str, str] = {}
    with zipfile.ZipFile(io.BytesIO(content)) as zf:
        candidates = [
            name for name in zf.namelist()
            if _is_supported(name)
            and not name.startswith("__MACOSX")
            and not name.endswith("/")   # skip directories
        ]
        if not candidates:
            raise HTTPException(
                status_code=400,
                detail="No supported source files found in the ZIP archive.",
            )

        candidates = candidates[:MAX_FILES_PER_SCAN]

        for name in candidates:
            info = zf.getinfo(name)
            if info.file_size > MAX_FILE_SIZE_BYTES:
                logger.warning(f"Skipping {name} — exceeds size limit ({info.file_size} bytes)")
                continue
            with zf.open(name) as f:
                files[name] = _safe_decode(f.read(), name)

    if not files:
        raise HTTPException(
            status_code=400,
            detail="All files in the ZIP were either too large or unsupported.",
        )
    return files


# ── Routes ────────────────────────────────────────────────────────────────────
@app.get("/health", tags=["ops"])
def health():
    """Liveness / readiness probe."""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=SecurityReport,
    responses={400: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    tags=["security"],
    summary="Analyze uploaded code for security vulnerabilities",
)
async def analyze(file: UploadFile = File(..., description="A source file or a .zip archive")):
    """
    Upload a single source file (e.g. `main.py`, `app.js`) **or** a `.zip`
    archive containing multiple files.

    Returns a JSON security report with every vulnerability found, its severity,
    the vulnerable code snippet, and a concrete fix suggestion.
    """
    raw = await file.read()
    filename = file.filename or "upload"

    logger.info(f"Received upload: {filename} ({len(raw)} bytes)")

    # ── Route by file type ────────────────────────────────────────────────────
    if filename.lower().endswith(".zip"):
        try:
            files_to_analyze = _extract_files_from_zip(raw)
        except zipfile.BadZipFile:
            raise HTTPException(status_code=400, detail="The uploaded file is not a valid ZIP archive.")
    else:
        if not _is_supported(filename):
            raise HTTPException(
                status_code=400,
                detail=f"Unsupported file type '{filename}'. "
                       f"Supported extensions: {', '.join(sorted(SUPPORTED_EXTENSIONS))}",
            )
        if len(raw) > MAX_FILE_SIZE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=f"File exceeds the {MAX_FILE_SIZE_BYTES // 1024} KB size limit.",
            )
        files_to_analyze = {filename: _safe_decode(raw, filename)}

    # ── Run analysis ──────────────────────────────────────────────────────────
    try:
        report = analyze_code(files_to_analyze)
    except ValueError as exc:
        # JSON extraction from LLM response failed
        logger.error(f"LLM response parsing error: {exc}")
        raise HTTPException(status_code=500, detail=f"Failed to parse LLM response: {exc}")
    except Exception as exc:
        logger.exception("Unexpected error during analysis")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {exc}")

    return report
