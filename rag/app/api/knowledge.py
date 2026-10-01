from fastapi import APIRouter, UploadFile, File, Form, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional

from app.services.knowledge_service import (
    create_knowledge_doc, update_knowledge_doc, delete_knowledge_doc,
    list_knowledge_docs, get_knowledge_doc, search_knowledge, stream_ask
)
from app.utils.logger import logger

router = APIRouter()


# ─── 增：直接输入文本 ────────────────────────────────────────────────────────

class KnowledgeCreate(BaseModel):
    title: str
    content: str

@router.post("/")
def create(req: KnowledgeCreate):
    if not req.title.strip() or not req.content.strip():
        raise HTTPException(status_code=400, detail="title 和 content 不能为空")
    try:
        result = create_knowledge_doc(req.title, req.content, source="direct_input")
        return {"code": 200, "data": result}
    except Exception as e:
        logger.error(f"create error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── 增：上传 txt 文件 ────────────────────────────────────────────────────────

@router.post("/upload")
async def upload_txt(
    file: UploadFile = File(...),
    title: Optional[str] = Form(None)
):
    if not file.filename.endswith(".txt"):
        raise HTTPException(status_code=400, detail="仅支持 .txt 文件")
    try:
        raw = await file.read()
        content = raw.decode("utf-8", errors="replace")
        if not content.strip():
            raise HTTPException(status_code=400, detail="文件内容为空")
        doc_title = (title or "").strip() or file.filename.replace(".txt", "")
        result = create_knowledge_doc(doc_title, content, source="file_upload", filename=file.filename)
        return {"code": 200, "data": result}
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"upload error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── 查：分页列表 ─────────────────────────────────────────────────────────────

@router.get("/")
def list_docs(page: int = 1, size: int = 10):
    try:
        result = list_knowledge_docs(page, size)
        return {"code": 200, "data": result}
    except Exception as e:
        logger.error(f"list error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── 查：单条 ─────────────────────────────────────────────────────────────────

@router.get("/{doc_id}")
def get_doc(doc_id: str):
    doc = get_knowledge_doc(doc_id)
    if not doc:
        raise HTTPException(status_code=404, detail="文档不存在")
    return {"code": 200, "data": doc}


# ─── 改 ───────────────────────────────────────────────────────────────────────

class KnowledgeUpdate(BaseModel):
    title: str
    content: str

@router.put("/{doc_id}")
def update(doc_id: str, req: KnowledgeUpdate):
    if not req.title.strip() or not req.content.strip():
        raise HTTPException(status_code=400, detail="title 和 content 不能为空")
    try:
        result = update_knowledge_doc(doc_id, req.title, req.content)
        return {"code": 200, "data": result}
    except Exception as e:
        logger.error(f"update error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── 删 ───────────────────────────────────────────────────────────────────────

@router.delete("/{doc_id}")
def delete(doc_id: str):
    try:
        result = delete_knowledge_doc(doc_id)
        return {"code": 200, "data": result}
    except Exception as e:
        logger.error(f"delete error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── 相关性检索（纯返回结果，不生成答案） ────────────────────────────────────

class SearchRequest(BaseModel):
    query: str
    top_k: int = 5

@router.post("/search")
def search(req: SearchRequest):
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="query 不能为空")
    try:
        results = search_knowledge(req.query, req.top_k)
        return {"code": 200, "data": results}
    except Exception as e:
        logger.error(f"search error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── 流式问答 ─────────────────────────────────────────────────────────────────

class AskRequest(BaseModel):
    query: str
    top_k: int = 3

@router.post("/ask")
def ask(req: AskRequest):
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="query 不能为空")
    try:
        gen = stream_ask(req.query, req.top_k)
        return StreamingResponse(gen, media_type="text/event-stream")
    except Exception as e:
        logger.error(f"ask error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
