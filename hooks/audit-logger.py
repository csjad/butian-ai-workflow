#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
audit-logger.py（hooks 便捷入口）— 转发到 scripts/audit_logger.py

保持 hooks/ 与 scripts/ 审计逻辑统一，避免重复实现。
用法同 scripts/audit_logger.py。
"""
from __future__ import annotations

import subprocess
import sys
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = os.path.join(ROOT, "scripts", "audit_logger.py")

if __name__ == "__main__":
    subprocess.run([sys.executable, CORE, *sys.argv[1:]])
