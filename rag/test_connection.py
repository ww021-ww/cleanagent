"""
连接测试脚本
运行: python test_connection.py
"""
import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

def test_es():
    print("=" * 50)
    print("【1】测试 Elasticsearch 连接")
    try:
        from app.es.client import es
        info = es.info()
        print(f"  ✅ 连接成功！版本: {info['version']['number']}")
        print(f"  集群名称: {info['cluster_name']}")
    except Exception as e:
        print(f"  ❌ 连接失败: {e}")
        return False
    return True

def test_create_indices():
    print("\n【2】测试自动创建知识库索引")
    try:
        from app.es.knowledge_index import ensure_indices
        from app.es.client import es
        from app.config.settings import KNOWLEDGE_INDEX, KNOWLEDGE_VEC_INDEX
        ensure_indices()
        exists_text = es.indices.exists(index=KNOWLEDGE_INDEX)
        exists_vec  = es.indices.exists(index=KNOWLEDGE_VEC_INDEX)
        print(f"  ✅ {KNOWLEDGE_INDEX}     索引: {'存在' if exists_text else '不存在'}")
        print(f"  ✅ {KNOWLEDGE_VEC_INDEX} 索引: {'存在' if exists_vec else '不存在'}")
    except Exception as e:
        print(f"  ❌ 索引创建失败: {e}")
        return False
    return True

def test_embedding():
    print("\n【3】测试 SiliconFlow BGE-M3 向量生成")
    try:
        from app.es.embeddings import generate_embeddings
        vecs = generate_embeddings("春天来了，花都开了。")
        dim = len(vecs[0])
        print(f"  ✅ 向量生成成功！维度: {dim}")
        if dim != 1024:
            print(f"  ⚠️  警告：维度为 {dim}，预期 1024，请检查 EMB_MODEL 配置")
    except Exception as e:
        print(f"  ❌ 向量生成失败: {e}")
        return False
    return True

def test_crud():
    print("\n【4】测试知识库增删查")
    try:
        from app.es.knowledge_index import add_knowledge, list_knowledge, delete_knowledge
        from app.es.client import es
        from app.config.settings import KNOWLEDGE_INDEX

        # 写入
        doc_id = add_knowledge(
            title="测试文档",
            content="这是一段测试内容，用于验证知识库的写入和查询功能。",
            source="test"
        )
        print(f"  ✅ 写入成功，doc_id: {doc_id}")

        # ES 刷新，让文档可被检索
        es.indices.refresh(index=KNOWLEDGE_INDEX)

        # 查询
        result = list_knowledge(page=1, size=5)
        print(f"  ✅ 分页查询成功，当前总文档数: {result['total']}")

        # 删除
        delete_knowledge(doc_id)
        es.indices.refresh(index=KNOWLEDGE_INDEX)
        result2 = list_knowledge(page=1, size=5)
        print(f"  ✅ 删除成功，删除后文档数: {result2['total']}")

    except Exception as e:
        print(f"  ❌ CRUD 测试失败: {e}")
        return False
    return True

def test_search():
    print("\n【5】测试混合检索（关键词 + 向量）")
    try:
        from app.es.knowledge_index import add_knowledge, delete_knowledge
        from app.services.knowledge_service import search_knowledge
        from app.es.client import es
        from app.config.settings import KNOWLEDGE_INDEX

        # 写入两条测试数据
        id1 = add_knowledge("朱自清《春》", "春天来了！东风来了，山朗润起来了，水涨起来了，太阳的脸红起来了。")
        id2 = add_knowledge("鲁迅《故乡》", "我冒了严寒，回到相隔二千余里，别了二十余年的故乡去。时候既然是深冬，渐近故乡时，天气又阴晦了。")
        es.indices.refresh(index=KNOWLEDGE_INDEX)

        # 搜索测试
        queries = ["春天", "少年闰土", "小孩子"]
        for q in queries:
            results = search_knowledge(q, top_k=2)
            titles = [r.get("title", "") for r in results]
            print(f"  查询「{q}」→ {titles}")

        # 清理测试数据
        delete_knowledge(id1)
        delete_knowledge(id2)
        print("  ✅ 检索测试完成，测试数据已清理")

    except Exception as e:
        print(f"  ❌ 检索测试失败: {e}")
        return False
    return True

if __name__ == "__main__":
    print("🚀 知识库 RAG 系统 - 连接测试")
    results = []
    results.append(test_es())
    if results[0]:
        results.append(test_create_indices())
        results.append(test_embedding())
        results.append(test_crud())
        results.append(test_search())

    print("\n" + "=" * 50)
    passed = sum(1 for r in results if r)
    print(f"测试结果: {passed}/{len(results)} 通过")
    if all(results):
        print("🎉 全部通过！项目可以正常运行。")
    else:
        print("⚠️  部分测试失败，请检查上方错误信息。")
