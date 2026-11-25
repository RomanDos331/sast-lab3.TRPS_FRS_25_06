import json
import re
from collections import Counter
from html import escape
from sqlalchemy.orm import Session
from . import models

class CodeFetcher:
    """Получает исходный код проекта из хранилища."""
    def fetch(self, db: Session, project_id: int) -> models.Project | None:
        return db.get(models.Project, project_id)

class RuleEngine:
    """Демонстрационный набор правил статического анализа."""
    RULES = [
        {
            "id": "SAST-SQL-001", "title": "Потенциальная SQL-инъекция",
            "description": "Обнаружено формирование SQL-запроса через f-строку или конкатенацию. Используйте параметризованные запросы.",
            "severity": "high",
            "pattern": re.compile(r"(?:execute|cursor\.execute)\s*\(\s*f['\"]|(?:SELECT|UPDATE|DELETE)\b.{0,80}\+\s*[A-Za-z_]", re.I),
        },
        {
            "id": "SAST-XSS-001", "title": "Потенциальная XSS",
            "description": "Обнаружено присваивание пользовательского содержимого в innerHTML. Используйте безопасный вывод/экранирование.",
            "severity": "high",
            "pattern": re.compile(r"\.innerHTML\s*="),
        },
        {
            "id": "SAST-SECRET-001", "title": "Возможный секрет в исходном коде",
            "description": "Обнаружено присваивание значения password, secret или api_key строковым литералом.",
            "severity": "critical",
            "pattern": re.compile(r"\b(?:password|secret|api_key)\s*=\s*['\"][^'\"]{6,}['\"]", re.I),
        },
    ]

    def inspect(self, source: str) -> list[dict]:
        candidates = []
        for line_number, line in enumerate(source.splitlines(), start=1):
            for rule in self.RULES:
                if rule["pattern"].search(line):
                    candidates.append({
                        "rule_id": rule["id"], "title": rule["title"],
                        "description": rule["description"], "severity": rule["severity"],
                        "file_path": "<source_code>", "line_number": line_number,
                        "code_snippet": line.strip()[:1000],
                    })
        return candidates

class AnalyzerCore:
    def __init__(self, rule_engine: RuleEngine | None = None):
        self.rule_engine = rule_engine or RuleEngine()

    def analyze(self, source: str) -> list[dict]:
        return self.rule_engine.inspect(source)

class QualityGateService:
    """Демонстрационный Quality Gate блокирует Critical и High находки."""
    def evaluate(self, findings: list[models.Finding], config: models.ThresholdConfig | None = None) -> dict:
        counts = Counter(item.severity for item in findings)
        critical, high = counts.get("critical", 0), counts.get("high", 0)
        max_critical = config.max_critical if config else 0
        max_high = config.max_high if config else 0
        passed = critical <= max_critical and high <= max_high
        return {
            "passed": passed, "critical_count": critical, "high_count": high,
            "medium_count": counts.get("medium", 0), "low_count": counts.get("low", 0),
            "max_critical": max_critical, "max_high": max_high,
            "message": "Проверка пройдена" if passed else "Проверка заблокирована: найдены уязвимости высокой критичности",
        }

class ReportGenerator:
    def generate(self, scan: models.ScanTask, findings: list[models.Finding], fmt: str) -> str:
        payload = {
            "scan_id": scan.id, "project_id": scan.project_id, "status": scan.status,
            "findings": [
                {"rule_id": f.rule_id, "title": f.title, "severity": f.severity,
                 "file_path": f.file_path, "line_number": f.line_number,
                 "description": f.description} for f in findings
            ],
        }
        if fmt == "json":
            return json.dumps(payload, ensure_ascii=False, indent=2)
        if fmt == "html":
            rows = "".join(
                f"<tr><td>{escape(f.severity)}</td><td>{escape(f.title)}</td><td>{escape(f.file_path)}:{f.line_number}</td></tr>"
                for f in findings
            )
            return ("<!doctype html><html lang='ru'><meta charset='utf-8'><title>SAST report</title>"
                    "<h1>Отчёт SAST</h1>" + f"<p>Сканирование #{scan.id}</p><table border='1'>"
                    "<tr><th>Критичность</th><th>Находка</th><th>Местоположение</th></tr>" + rows +
                    "</table></html>")
        if fmt == "sarif":
            results = [{
                "ruleId": f.rule_id,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(f.severity, "warning"),
                "message": {"text": f.title + ": " + f.description},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file_path},
                    "region": {"startLine": f.line_number}}}],
            } for f in findings]
            return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                               "runs": [{"tool": {"driver": {"name": "SAST Prototype"}}, "results": results}]},
                              ensure_ascii=False, indent=2)
        raise ValueError("Неподдерживаемый формат отчёта")
