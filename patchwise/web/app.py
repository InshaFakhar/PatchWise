"""FastAPI web interface. Routes are thin: they call patchwise.services."""

from pathlib import Path

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.templating import Jinja2Templates

from patchwise import services
from patchwise.db.connection import init_db

TEMPLATES_DIR = Path(__file__).parent / "templates"


def create_app(db_path=None):
    """Build the app. Tests pass a temporary db_path; normal use passes None."""
    app = FastAPI(title="PatchWise")
    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    init_db(db_path)

    def read_upload(file: UploadFile):
        # Read at most limit+1 bytes: a huge file is detected without loading it all.
        return file.file.read(services.MAX_UPLOAD_BYTES + 1)

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/")
    def index(request: Request):
        assets = services.list_assets(db_path)
        return templates.TemplateResponse(request, "index.html", {"assets": assets})

    @app.get("/assets/{asset_id}")
    def asset_detail(request: Request, asset_id: str):
        asset = services.get_asset(asset_id, db_path)
        if asset is None:
            raise HTTPException(status_code=404, detail="Asset not found")
        return templates.TemplateResponse(request, "asset.html", {"asset": asset})

    @app.get("/upload")
    def upload_form(request: Request):
        assets = services.list_assets(db_path)
        return templates.TemplateResponse(request, "upload.html", {"assets": assets})

    @app.post("/upload/inventory")
    def upload_inventory(request: Request, file: UploadFile = File(...)):
        view = services.import_inventory_upload(read_upload(file), db_path)
        return templates.TemplateResponse(request, "report.html", {"view": view})

    @app.post("/upload/sbom")
    def upload_sbom(request: Request, asset_id: str = Form(""), file: UploadFile = File(...)):
        view = services.import_sbom_upload(read_upload(file), asset_id, db_path)
        return templates.TemplateResponse(request, "report.html", {"view": view})

    return app