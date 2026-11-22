"""FastAPI web interface. Routes are thin: they call patchwise.services."""

from pathlib import Path
from urllib.parse import quote

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import RedirectResponse, Response
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

    @app.get("/findings")
    def findings(request: Request):
        rows = services.list_findings(db_path)
        counts = services.count_by_status(rows)
        return templates.TemplateResponse(
            request, "findings.html", {"findings": rows, "counts": counts}
        )

    @app.get("/ranking")
    def ranking(request: Request):
        return templates.TemplateResponse(
            request, "ranking.html",
            {
                "ranked": services.list_ranked(db_path),
                "weights": services.weight_shares(),
                "sensitivity": services.sensitivity_report(db_path),
            },
        )

    @app.get("/queue")
    def queue_page(request: Request):
        queue = services.list_queue(db_path)
        error = request.query_params.get("error", "")[:200]
        return templates.TemplateResponse(
            request, "queue.html",
            {
                "queue": queue,
                "counts": services.queue_counts(queue),
                "analyst": request.cookies.get("analyst", ""),
                "error": error,
            },
        )

    @app.post("/review/decide")
    def review_decide(
        component_id: str = Form(""),
        cve_id: str = Form(""),
        action: str = Form(""),
        reason: str = Form(""),
        analyst: str = Form(""),
    ):
        try:
            services.record_decision(component_id, cve_id, action, reason, analyst, db_path)
        except ValueError as exc:
            return RedirectResponse("/queue?error=" + quote(str(exc)[:200]), status_code=303)
        response = RedirectResponse("/queue", status_code=303)
        response.set_cookie("analyst", analyst.strip()[:80], httponly=True, samesite="lax")
        return response

    @app.get("/audit")
    def audit_page(request: Request):
        return templates.TemplateResponse(
            request, "audit.html", {"history": services.list_audit(db_path)})

    @app.get("/export/queue.csv")
    def export_csv():
        # utf-8 with a byte-order mark so Excel opens non-English text correctly
        body = services.export_queue_csv(db_path).encode("utf-8-sig")
        return Response(
            body, media_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="patchwise_queue.csv"'})

    @app.get("/export/queue.md")
    def export_markdown():
        body = services.export_queue_markdown(db_path).encode("utf-8")
        return Response(
            body, media_type="text/markdown; charset=utf-8",
            headers={"Content-Disposition": 'attachment; filename="patchwise_queue.md"'})

    @app.post("/matching/run")
    def matching_run():
        services.run_matching(db_path)
        return RedirectResponse("/findings", status_code=303)

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
