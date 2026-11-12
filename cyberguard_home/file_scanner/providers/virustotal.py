from pathlib import Path

from ..models import Finding, ProviderReport, VtReport, VtStatus
from ..vt_client import VirusTotalClient

_NOTES = {
    VtStatus.NO_KEY: "Проверка по онлайн-базе не выполнена: не указан ключ.",
    VtStatus.BAD_KEY: "Проверка по онлайн-базе не выполнена: ключ не подошёл.",
    VtStatus.RATE_LIMITED: "Проверка по онлайн-базе отложена: исчерпан лимит запросов. Повторите позже.",
    VtStatus.ERROR: "Проверка по онлайн-базе не выполнена: не удалось связаться с сервисом.",
}


class VirusTotalProvider:
    """Только по хэшу. Подключается лишь при подтверждённой лицензии (см. build_providers)."""
    name = "virustotal"

    def __init__(self, client: VirusTotalClient) -> None:
        self._client = client

    def close(self) -> None:
        self._client.close()

    def check(self, path: Path, sha256: str) -> ProviderReport:
        report: VtReport = self._client.lookup(sha256)
        if report.status is VtStatus.NOT_FOUND:
            return ProviderReport(self.name, True, (Finding(
                "vt_unknown",
                "Такого файла нет в онлайн-базе. Для новых и редких файлов это нормально, "
                "но подтвердить безопасность по базе мы не можем.", 0),))
        if report.status is not VtStatus.FOUND:
            return ProviderReport(self.name, False, note=_NOTES.get(report.status, _NOTES[VtStatus.ERROR]))

        tech = (f"VT: malicious={report.malicious}, suspicious={report.suspicious}, "
                f"harmless={report.harmless}, undetected={report.undetected}")
        if report.malicious >= 5:
            f = Finding("vt_malicious",
                        f"Антивирусы ({report.malicious} из {report.total}) считают этот файл вредоносным.", 100, tech)
        elif report.malicious >= 1:
            f = Finding("vt_few_detections",
                        f"Несколько антивирусов ({report.malicious}) сочли файл опасным. "
                        "Возможно, это ложная тревога, но будьте осторожны.", 40, tech)
        elif report.suspicious >= 3:
            f = Finding("vt_suspicious",
                        f"Несколько антивирусов ({report.suspicious}) считают файл подозрительным.", 30, tech)
        else:
            f = Finding("vt_clean", "Файл известен антивирусным сервисам, угроз они не нашли.", 0, tech)
        return ProviderReport(self.name, True, (f,))