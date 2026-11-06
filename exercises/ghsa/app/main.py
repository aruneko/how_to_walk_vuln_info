"""研究室の画像変換 API

- POST /convert      : アップロードされた画像を PNG に変換して返す（誰でも利用できる）
- GET  /admin/stats  : 利用状況を返す（管理者のみ）
"""
import io
import os

import jwt
from fastapi import FastAPI, File, Request, UploadFile
from fastapi.responses import JSONResponse, Response
from PIL import Image

app = FastAPI()

# JWT の署名検証に使う共通鍵（HS256）。サーバーの環境変数で設定する
SECRET = os.environ["JWT_SECRET"]


@app.middleware("http")
async def admin_guard(request: Request, call_next):
    """/admin 以下へのアクセスは、role が admin の JWT を持つ人だけに許可する"""
    if request.url.path.startswith("/admin"):
        token = request.headers.get("Authorization", "").removeprefix("Bearer ")
        try:
            claims = jwt.decode(token, SECRET, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return JSONResponse({"detail": "forbidden"}, status_code=403)
        if claims.get("role") != "admin":
            return JSONResponse({"detail": "forbidden"}, status_code=403)
    return await call_next(request)


@app.post("/convert")
async def convert(file: UploadFile = File(...)):
    """アップロードされた画像を PNG に変換する（Pillow が読める形式なら何でも受け付ける）"""
    image = Image.open(io.BytesIO(await file.read()))
    out = io.BytesIO()
    image.save(out, format="PNG")
    return Response(out.getvalue(), media_type="image/png")


@app.get("/admin/stats")
async def admin_stats():
    return {"converted": 1234, "users": 56}
