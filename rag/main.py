import os
import uvicorn
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from app.api.knowledge import router as knowledge_router
from app.utils.logger import logger

app = FastAPI(
    title="知识库 RAG 系统",
    description="支持 txt 上传 / 文本输入 / 混合检索 / 流式问答"
)

# 挂载前端静态文件
frontend_dir = os.path.join(os.path.dirname(__file__), "frontend")
if os.path.exists(frontend_dir):
    app.mount("/frontend", StaticFiles(directory=frontend_dir), name="frontend")

# 知识库路由（/knowledge 前缀）
app.include_router(knowledge_router, prefix="/knowledge", tags=["知识库"])


@app.get("/")
def index():
    index_file = os.path.join(frontend_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "知识库 RAG 系统已启动", "docs": "/docs"}


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    logger.info("启动知识库 RAG 系统...")
    uvicorn.run("main:app", host="0.0.0.0", port=8002, reload=True)
