"""
ASHWIN Bounded Ephemeral Short-Term Memory (Phase 3 / Stage E).
RAM-only, bounded FIFO retention in UTF-8 bytes and item count.
Strict secret scanning, classification inheritance, and Router-ingress gating (RULE-03, RULE-04, RULE-05).
"""

import time
import uuid
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from ashwin.core.models import (
    DataClass,
    SourceDomain,
    ScannedClassifiedContext,
    RouterGateError,
    SecurityViolation,
)
from ashwin.core.secret_scanner import SecretScanner


DEFAULT_MAX_ITEMS = 20
DEFAULT_MAX_TOTAL_BYTES = 32_000


@dataclass(frozen=True)
class MemoryItem:
    item_id: str
    content: str
    data_class: DataClass
    source: SourceDomain
    timestamp: float
    byte_size: int
    metadata: Dict[str, Any] = field(default_factory=dict)
    scanned: bool = True


class EphemeralMemoryStore:
    """
    RAM-only ephemeral short-term memory with bounded FIFO retention in UTF-8 bytes and item count.
    Enforces secret scanning at insertion, blocks HIGHLY_PROTECTED material,
    and calculates classification inheritance upon recall.
    """

    def __init__(
        self,
        scanner: Optional[SecretScanner] = None,
        max_items: int = DEFAULT_MAX_ITEMS,
        max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    ):
        if max_items <= 0:
            raise ValueError("max_items must be positive.")
        if max_total_bytes <= 0:
            raise ValueError("max_total_bytes must be positive.")

        self.scanner = scanner or SecretScanner()
        self.max_items = max_items
        self.max_total_bytes = max_total_bytes
        self._items: List[MemoryItem] = []
        self._total_bytes: int = 0

    @property
    def count(self) -> int:
        return len(self._items)

    @property
    def total_bytes(self) -> int:
        return self._total_bytes

    def add_context(self, context: ScannedClassifiedContext) -> MemoryItem:
        """
        Stores an already-validated ScannedClassifiedContext item into memory.
        Enforces scan health and RULE-03 (blocks HIGHLY_PROTECTED).
        """
        if not isinstance(context, ScannedClassifiedContext):
            raise RouterGateError("RULE-04 Violation: Object is not a valid ScannedClassifiedContext instance.")

        if not context.scanned or not context.scan_summary.get("healthy", False):
            raise RouterGateError("RULE-04 Violation: Missing valid scan state.")

        if context.data_class == DataClass.HIGHLY_PROTECTED:
            raise SecurityViolation("RULE-03 Violation: HIGHLY_PROTECTED data cannot enter memory.")

        return self._insert_item(
            content=context.content,
            data_class=context.data_class,
            source=context.source,
            metadata=context.metadata
        )

    def add_user_input(
        self,
        raw_text: str,
        source: SourceDomain = SourceDomain.PHONE,
        is_stt: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> MemoryItem:
        """
        Scans, classifies, and inserts raw user input (typed or STT).
        Defaults to PROTECTED per Section 4.3.
        """
        if not self.scanner.is_healthy():
            raise RouterGateError("Memory insertion rejected: SecretScanner is unhealthy.")

        redacted_content, scan_summary, assessed_class = self.scanner.scan_and_redact(raw_text)

        final_class = DataClass.PROTECTED
        if assessed_class == DataClass.HIGHLY_PROTECTED:
            raise SecurityViolation("RULE-03 Violation: HIGHLY_PROTECTED material detected; blocked from memory.")

        meta = dict(metadata or {})
        meta["input_type"] = "STT" if is_stt else "TYPED_TEXT"
        meta["redaction_count"] = scan_summary.get("redaction_count", 0)

        return self._insert_item(
            content=redacted_content,
            data_class=final_class,
            source=source,
            metadata=meta
        )

    def _insert_item(
        self,
        content: str,
        data_class: DataClass,
        source: SourceDomain,
        metadata: Optional[Dict[str, Any]] = None
    ) -> MemoryItem:
        """
        Internal insertion establishing scanned trust state and enforcing FIFO byte/item bounds.
        """
        if data_class == DataClass.HIGHLY_PROTECTED:
            raise SecurityViolation("RULE-03 Violation: HIGHLY_PROTECTED data cannot be stored in memory.")

        utf8_bytes = content.encode("utf-8")
        byte_size = len(utf8_bytes)

        item = MemoryItem(
            item_id=str(uuid.uuid4()),
            content=content,
            data_class=data_class,
            source=source,
            timestamp=time.time(),
            byte_size=byte_size,
            metadata=metadata or {},
            scanned=True
        )

        # Enforce bounds before inserting
        self._items.append(item)
        self._total_bytes += byte_size

        self._evict_excess()
        return item

    def _evict_excess(self):
        """
        Evicts oldest items (FIFO) until item count and total UTF-8 byte limits are respected.
        """
        while len(self._items) > self.max_items:
            evicted = self._items.pop(0)
            self._total_bytes -= evicted.byte_size

        while self._total_bytes > self.max_total_bytes and self._items:
            evicted = self._items.pop(0)
            self._total_bytes -= evicted.byte_size

    def recall_context(self, max_items: Optional[int] = None) -> ScannedClassifiedContext:
        """
        Recalls conversation context into a validated ScannedClassifiedContext.
        Applies highest-classification inheritance:
        HIGHLY_PROTECTED > PROTECTED > PERSONAL > PUBLIC.
        Fails closed if any item is unscanned or HIGHLY_PROTECTED.
        """
        if not self._items:
            return ScannedClassifiedContext(
                content="",
                data_class=DataClass.PUBLIC,
                source=SourceDomain.PHONE,
                scanned=True,
                scan_summary={"healthy": True, "memory_items_count": 0},
                metadata={"recalled_items_count": 0}
            )

        items_to_recall = self._items[-max_items:] if max_items else list(self._items)

        # Determine inherited classification
        # Classification Priority: HIGHLY_PROTECTED > PROTECTED > PERSONAL > PUBLIC
        has_highly_protected = False
        has_protected = False
        has_personal = False

        consolidated_texts = []
        for it in items_to_recall:
            if not it.scanned:
                raise RouterGateError("RULE-04 Violation: Unscanned item found in memory store.")
            if it.data_class == DataClass.HIGHLY_PROTECTED:
                has_highly_protected = True
            elif it.data_class == DataClass.PROTECTED:
                has_protected = True
            elif it.data_class == DataClass.PERSONAL:
                has_personal = True

            consolidated_texts.append(it.content)

        if has_highly_protected:
            raise SecurityViolation("RULE-03 Violation: HIGHLY_PROTECTED item encountered during memory recall.")

        if has_protected:
            inherited_class = DataClass.PROTECTED
        elif has_personal:
            inherited_class = DataClass.PERSONAL
        else:
            inherited_class = DataClass.PUBLIC

        combined_content = "\n".join(consolidated_texts)

        return ScannedClassifiedContext(
            content=combined_content,
            data_class=inherited_class,
            source=SourceDomain.PHONE,
            scanned=True,
            scan_summary={
                "healthy": True,
                "memory_items_count": len(items_to_recall)
            },
            metadata={
                "recalled_items_count": len(items_to_recall),
                "total_memory_bytes": sum(it.byte_size for it in items_to_recall)
            }
        )

    def get_items(self) -> List[MemoryItem]:
        return list(self._items)

    def clear(self):
        """Explicitly wipes all ephemeral memory items and counters."""
        self._items.clear()
        self._total_bytes = 0

    def reset(self):
        self.clear()
