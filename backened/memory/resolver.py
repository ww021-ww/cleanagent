import re
from typing import Dict, Optional

from memory.session import SessionState


class ReferenceResolver:
    def __init__(self):
        self._correction_patterns = [
            r"不[，,\s]*我指的不是这个漏洞",
            r"不是这个",
            r"你理解错了",
            r"我说的不是上一条",
            r"不是第一个[，,\s]*是第二个",
        ]
        self._result_set_tokens = [
            "这个搜索结果", "这个结果", "上面的结果", "刚刚查到的", "刚才那个结果", "这批结果", "这些结果",
        ]

    def detect_correction(self, message: str) -> Dict:
        normalized = re.sub(r"\s+", "", message)
        for pattern in self._correction_patterns:
            if re.search(pattern, normalized, re.I):
                return {"is_correction": True, "message": message}
        return {"is_correction": False}

    def resolve_message(self, message: str, state: Optional[SessionState]) -> Dict:
        correction = self.detect_correction(message)
        if correction.get("is_correction"):
            explicit_id = self._extract_explicit_vuln_id(message)
            if explicit_id:
                return {
                    "message": message,
                    "resolved_vuln_id": explicit_id,
                    "resolved_target_type": "vuln",
                    "resolved_result_index": -1,
                    "requires_reset": True,
                    "requires_clarification": False,
                }
            if state and len(state.last_result_ids) >= 2 and "第二个" in message:
                vuln_id = state.last_result_ids[1]
                rewritten = message.replace("第二个", vuln_id)
                return {
                    "message": rewritten,
                    "resolved_vuln_id": vuln_id,
                    "resolved_target_type": "vuln",
                    "resolved_result_index": 1,
                    "requires_reset": True,
                    "requires_clarification": False,
                }
            if state and state.last_result_ids and "第一个" in message:
                vuln_id = state.last_result_ids[0]
                rewritten = message.replace("第一个", vuln_id)
                return {
                    "message": rewritten,
                    "resolved_vuln_id": vuln_id,
                    "resolved_target_type": "vuln",
                    "resolved_result_index": 0,
                    "requires_reset": True,
                    "requires_clarification": False,
                }
            return {
                "message": message,
                "resolved_vuln_id": "",
                "resolved_target_type": "none",
                "resolved_result_index": -1,
                "requires_reset": True,
                "requires_clarification": True,
            }
        if not state:
            return {
                "message": message,
                "resolved_vuln_id": "",
                "resolved_target_type": "none",
                "resolved_result_index": -1,
                "requires_reset": False,
                "requires_clarification": False,
            }
        if state.last_result_preview and any(token in message for token in self._result_set_tokens):
            return {
                "message": message,
                "resolved_vuln_id": state.active_vuln_id,
                "resolved_target_type": "result_set",
                "resolved_result_index": -1,
                "requires_reset": False,
                "requires_clarification": False,
            }
        if state.active_vuln_id and any(token in message for token in ["这个漏洞", "它", "该漏洞", "刚才那个"]):
            rewritten = re.sub(r"这个漏洞|该漏洞|刚才那个|它", state.active_vuln_id, message)
            return {
                "message": rewritten,
                "resolved_vuln_id": state.active_vuln_id,
                "resolved_target_type": "vuln",
                "resolved_result_index": -1,
                "requires_reset": False,
                "requires_clarification": False,
            }
        if state.last_result_ids and "第一个" in message:
            vuln_id = state.last_result_ids[0]
            rewritten = message.replace("第一个", vuln_id)
            return {
                "message": rewritten,
                "resolved_vuln_id": vuln_id,
                "resolved_target_type": "vuln",
                "resolved_result_index": 0,
                "requires_reset": False,
                "requires_clarification": False,
            }
        if len(state.last_result_ids) >= 2 and "第二个" in message:
            vuln_id = state.last_result_ids[1]
            rewritten = message.replace("第二个", vuln_id)
            return {
                "message": rewritten,
                "resolved_vuln_id": vuln_id,
                "resolved_target_type": "vuln",
                "resolved_result_index": 1,
                "requires_reset": False,
                "requires_clarification": False,
            }
        return {
            "message": message,
            "resolved_vuln_id": state.active_vuln_id,
            "resolved_target_type": "none",
            "resolved_result_index": -1,
            "requires_reset": False,
            "requires_clarification": False,
        }

    @staticmethod
    def _extract_explicit_vuln_id(message: str) -> str:
        match = re.search(r"(CVE-\d{4}-\d+|CNVD-\d{4}-\d+|JVNVU?#?\d+)", message, re.I)
        return match.group(1) if match else ""
