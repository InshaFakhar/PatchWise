from fastapi import FastAPI

app = FastAPI(title="PatchWise")

@app.get("/health")
def health():
    return {"status": "ok"}