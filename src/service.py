from . import domain, rules
from .domain import DomainError

FROZEN_BY_FORK_ACTIONS = {"approve", "execute"}


class Service:
    def __init__(self, repository):
        self.repository = repository

    def create_item(self, payload, actor, role, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.CREATE_ROLES:
            raise DomainError("forbidden", "当前角色不能创建此类业务记录", 403)
        normalized = domain.normalize_create(payload)
        stable_key = normalized.pop("_stable_key")
        return self.repository.create_item(
            rules.ENTITY_TYPE, stable_key, rules.INITIAL_STATUS, normalized, actor, role
        )

    def add_source(self, item_id, payload, actor, role, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in rules.SOURCE_ROLES:
            raise DomainError("forbidden", "当前角色不能提交来源记录", 403)
        item = self.repository.get_item(item_id)
        normalized = domain.normalize_source(payload)
        if region and rules.ENFORCE_REGION and role != "regulator" and normalized.get("region") and normalized["region"] != region:
            raise DomainError("region_mismatch", "来源记录不属于当前管辖区域", 403)
        result = self.repository.add_source(
            item_id,
            normalized.pop("source_type"),
            normalized.pop("external_id"),
            normalized,
            normalized.pop("observed_at"),
            actor,
            role,
        )
        return result

    def act(self, item_id, action, payload, actor, role, expected_version=None, region=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        item = self.repository.get_item(item_id)
        allowed = rules.ACTION_ROLES.get(action, set())
        if role not in allowed:
            raise DomainError("forbidden", "当前角色不能执行该操作", 403)
        if rules.ENFORCE_REGION and action in rules.REGION_SENSITIVE_ACTIONS and region and role != "regulator":
            if item["payload"].get("region") != region:
                raise DomainError("region_mismatch", "不能处理其他区域的记录", 403)
        if action in FROZEN_BY_FORK_ACTIONS and self.repository.is_quarantined_open(item_id):
            raise DomainError("event_quarantined", "该事件因总账分叉被停止批准和下发", 409)
        if action in rules.ACTION_REQUIRES_VERSION and expected_version is None:
            raise DomainError("expected_version_required", "该操作需要 expected_version", 400)
        new_status, new_payload, event_payload = rules.apply_action(item, action, payload, actor, role)
        self.repository.apply_action(
            item_id, action, actor, role, new_status, new_payload, event_payload, expected_version
        )
        return self.get_item(item_id)

    def get_item(self, item_id):
        item = self.repository.get_item(item_id)
        item["sources"] = self.repository.list_sources(item_id)
        item["assessment"] = rules.assess(item["payload"])
        item["quarantined"] = self.repository.is_quarantined_open(item["id"])
        ledger = self.repository.item_ledger(item_id)
        item["audit"] = ledger["events"]
        item["audit_chain"] = ledger["chain"]
        return item

    def list_items(self, status=None):
        items = self.repository.list_items(status)
        quarantined = {row["item_id"] for row in self.repository.list_quarantined()}
        for item in items:
            item["quarantined"] = item["id"] in quarantined
        return items

    def state(self):
        return self.repository.state_summary()

    # ------------------------------------------------------------------
    # 审计总账：按事件查阅 + 整库连续总账
    # ------------------------------------------------------------------
    def item_audit(self, item_id):
        return self.repository.item_ledger(item_id)

    def ledger(self):
        return self.repository.global_ledger()

    def register_receipt(self, period, seq, anchor, actor, role, note=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role != "regulator":
            raise DomainError("forbidden", "只有监管能登记回执锚值", 403)
        if not isinstance(period, str) or not period.strip():
            raise DomainError("field_required", "季度标识 period 不能为空")
        if not isinstance(anchor, str) or not anchor.strip():
            raise DomainError("field_required", "回执锚值 anchor 不能为空")
        if isinstance(seq, bool):
            raise DomainError("invalid_integer", "链位 seq 必须是整数")
        try:
            seq = int(seq)
        except (TypeError, ValueError):
            raise DomainError("invalid_integer", "链位 seq 必须是整数")
        return self.repository.register_receipt(period.strip(), seq, anchor.strip(), actor, note)

    def reconcile(self, payload, actor, role):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role not in {"regulator", "coordinator"}:
            raise DomainError("forbidden", "只有监管或协调员能发起对账", 403)
        enforce = payload.get("enforce", True)
        if not isinstance(enforce, bool):
            raise DomainError("invalid_flag", "enforce 必须是布尔值")
        anchors_input = payload.get("anchors")
        anchors = None
        if anchors_input is not None:
            if not isinstance(anchors_input, list):
                raise DomainError("invalid_anchors", "anchors 必须是回执锚值列表")
            anchors = []
            for entry in anchors_input:
                if not isinstance(entry, dict) or not isinstance(entry.get("anchor"), str) or not entry["anchor"].strip():
                    raise DomainError("invalid_anchors", "每条锚值必须含 seq 与 anchor")
                if isinstance(entry.get("seq"), bool):
                    raise DomainError("invalid_anchors", "锚值链位必须是整数")
                try:
                    seq = int(entry["seq"])
                except (KeyError, TypeError, ValueError):
                    raise DomainError("invalid_anchors", "锚值链位必须是整数")
                anchors.append({"seq": seq, "anchor": entry["anchor"].strip()})
        return self.repository.reconcile(anchors=anchors, enforce=enforce, actor=actor)

    def release_quarantine(self, item_id, actor, role, note=None):
        if not actor or not role:
            raise DomainError("identity_required", "需要用户身份和角色", 401)
        if role != "regulator":
            raise DomainError("forbidden", "只有监管能解除隔离", 403)
        self.repository.release_quarantine(item_id, actor, note)
        return {"item_id": item_id, "released": True}
