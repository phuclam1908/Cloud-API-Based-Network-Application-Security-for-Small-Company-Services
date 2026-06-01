from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
import os

app = FastAPI()

@app.get("/")
async def root():
    return FileResponse("/app/index.html")

@app.get("/{path:path}")
async def catch_all(path: str):
    return FileResponse("/app/index.html")
