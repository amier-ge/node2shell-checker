from __future__ import annotations
import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from colorama import Fore, Style, init


AUTHOR = "amier_ge"
FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
SKIP_DIRS = {"node_modules", ".git", ".next", "dist", "build", "coverage", ".cache", "public"}
SOURCE_EXTS = {".js", ".cjs", ".mjs", ".ts", ".tsx"}
PATTERNS = [
    ("direct-brotli", re.compile(r"\b(?:createBrotliDecompress|brotliDecompress(?:Sync)?)\b"), "직접 Brotli 해제 호출"),
    ("request-parser", re.compile(r"\b(?:express|bodyParser)\.(?:json|raw|text|urlencoded)\s*\("), "압축된 요청 본문을 해제할 수 있는 미들웨어"),
    ("response-fetch", re.compile(r"\bfetch\s*\("), "Brotli 응답을 자동 해제할 수 있는 fetch 호출"),
]
VERSION_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)(?:[-+][\w.-]+)?$")


def iter_files(root: Path):
    for directory, subdirs, filenames in os.walk(root, followlinks=False):
        subdirs[:] = [name for name in subdirs if name not in SKIP_DIRS and not name.startswith('.research')]
        for name in filenames:
            yield Path(directory) / name


def version_status(value: str) -> str:
    match = VERSION_RE.fullmatch(value.strip())
    if not match:
        return "unknown"
    version = tuple(map(int, match.groups()))
    if version[0] not in FIXED:
        return "unsupported-or-unassessed"
    return "fixed" if version >= FIXED[version[0]] else "affected"


def command_version(command: list[str]) -> tuple[str | None, str | None]:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=8, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    if result.returncode != 0:
        return None, (result.stderr or result.stdout).strip() or f"종료 코드 {result.returncode}"
    value = result.stdout.strip()
    if not VERSION_RE.fullmatch(value):
        return None, f"Node 버전 형식을 인식하지 못함: {value[:100]}"
    return value.lstrip("v"), None


def resolve_project_dir(value: str) -> Path | None:
    path = Path(value).expanduser().resolve()
    return path if path.is_dir() else None


def evidence(path: Path, root: Path, label: str, version: str, kind: str) -> dict:
    return {"file": str(path.relative_to(root)), "source": label, "version": version,
            "status": version_status(version) if kind == "exact" else "unknown", "kind": kind}


def scan_versions(root: Path) -> list[dict]:
    found = []
    for path in iter_files(root):
        if path.name in {".nvmrc", ".node-version"}:
            value = path.read_text(encoding="utf-8", errors="replace").strip()
            found.append(evidence(path, root, path.name, value, "exact" if VERSION_RE.fullmatch(value) else "range"))
        elif path.name == "package.json":
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            value = data.get("engines", {}).get("node") if isinstance(data.get("engines"), dict) else None
            if isinstance(value, str):
                found.append(evidence(path, root, "engines.node", value, "exact" if VERSION_RE.fullmatch(value) else "range"))
        elif path.name.lower().startswith("dockerfile") or path.name == "Containerfile":
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            arg_defaults = {}
            for line in lines:
                arg = re.search(r"^\s*ARG\s+(\w+)=(\S+)", line, re.I)
                if arg:
                    arg_defaults[arg.group(1)] = arg.group(2)
            for line_no, line in enumerate(lines, 1):
                match = re.search(r"^\s*FROM\s+(?:--platform=\S+\s+)?(?:[\w.-]+/)*node:(\S+)", line, re.I)
                if match:
                    value = match.group(1).split("@")[0].split("-")[0]
                    if value.startswith("${") and value.endswith("}"):
                        value = arg_defaults.get(value[2:-1], value)
                    elif value.startswith("$"):
                        value = arg_defaults.get(value[1:], value)
                    item = evidence(path, root, f"FROM node: (line {line_no})", value,
                                    "exact" if VERSION_RE.fullmatch(value) else "range")
                    found.append(item)
        elif path.name.startswith("compose") and path.suffix in {".yml", ".yaml"}:
            for line_no, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                match = re.search(r"\bNODE_VERSION:\s*['\"]?(v?\d+\.\d+\.\d+)", line)
                if match:
                    found.append(evidence(path, root, f"NODE_VERSION (line {line_no})", match.group(1), "exact"))
    return found


def scan_source(root: Path) -> list[dict]:
    found = []
    for path in iter_files(root):
        if path.suffix not in SOURCE_EXTS:
            continue
        try:
            if path.stat().st_size > 1_000_000:
                continue
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, 1):
            if line.lstrip().startswith(("//", "*", "/*")) or re.search(r"\binflate\s*:\s*false\b", line):
                continue
            for kind, pattern, description in PATTERNS:
                if pattern.search(line):
                    found.append({"file": str(path.relative_to(root)), "line": line_no, "kind": kind,
                                  "description": description, "code": line.strip()[:160]})
    return found


def assess(runtime: dict | None, versions: list[dict], paths: list[dict]) -> str:
    if runtime and runtime["status"] == "fixed":
        return "PATCHED_RUNTIME"
    if runtime and runtime["status"] == "affected":
        return "HIGH_EXPOSURE" if paths else "AFFECTED_RUNTIME"
    pinned = [item for item in versions if item["status"] == "affected"]
    if pinned:
        return "POTENTIAL_EXPOSURE" if paths else "AFFECTED_VERSION_PIN"
    if paths:
        return "REVIEW_RUNTIME"
    return "NO_EVIDENCE"


def print_report(report: dict, color: bool) -> None:
    init(strip=not color)
    status = report["assessment"]
    shade = Fore.RED if status == "HIGH_EXPOSURE" else Fore.YELLOW if status != "PATCHED_RUNTIME" else Fore.GREEN
    result_text = {
        "HIGH_EXPOSURE": ("높은 위험 가능성", "실행 중인 Node가 취약 버전이고 관련 코드도 발견됐습니다."),
        "AFFECTED_RUNTIME": ("실행 중인 Node가 취약 버전", "관련 코드는 찾지 못했습니다. 입력 경로를 더 확인하세요."),
        "POTENTIAL_EXPOSURE": ("취약 가능성 있음", "프로젝트 파일에서 취약 버전과 관련 코드를 찾았습니다. 실행 중인 버전은 아직 모릅니다."),
        "AFFECTED_VERSION_PIN": ("취약 버전이 지정됨", "프로젝트 파일에 취약 버전이 있지만 관련 코드는 찾지 못했습니다."),
        "PATCHED_RUNTIME": ("확인한 Node는 수정 버전", "확인한 실행 버전은 수정 버전입니다. 다른 배포 환경도 확인하세요."),
        "REVIEW_RUNTIME": ("실행 버전 확인 필요", "관련 코드는 있지만 실제로 실행 중인 Node 버전을 모릅니다."),
        "NO_EVIDENCE": ("검사한 파일에서 단서 없음", "이 결과만으로 안전하다고 판단할 수는 없습니다."),
    }
    version_text = {
        "affected": "수정 전 버전", "fixed": "수정 버전",
        "unknown": "정확한 버전 미확인", "unsupported-or-unassessed": "비교 범위 밖",
    }
    code_text = {
        "direct-brotli": "Brotli 압축을 직접 해제하는 코드",
        "request-parser": "압축된 요청 본문을 해제할 수 있는 코드",
        "response-fetch": "압축된 응답을 받을 수 있는 fetch() 코드",
    }
    title, meaning = result_text[status]

    print(Fore.CYAN + f"Node2Shell 점검기 | 작성자 {AUTHOR}" + Style.RESET_ALL)
    print(f"검사 대상: {report['target']}")
    print(shade + f"결과: {title}" + Style.RESET_ALL)
    print(f"뜻: {meaning}")

    if report["runtime"]:
        runtime = report["runtime"]
        print(f"\n확인한 Node: {runtime['version']} ({version_text.get(runtime['status'], '상태 미확인')})")
        print(f"확인 위치: {runtime['source']}")

    if report["version_evidence"] or report["code_paths"]:
        print("\n찾은 근거:")
    for item in report["version_evidence"]:
        line = re.search(r"\(line (\d+)\)", item["source"])
        location = item["file"] + (f":{line.group(1)}" if line else "")
        label = version_text.get(item["status"], "상태 미확인")
        if item["kind"] != "exact":
            label = "버전 범위만 지정됨"
        print(f"  - {location}: Node {item['version']} ({label})")
    for item in report["code_paths"]:
        label = code_text.get(item["kind"], "관련 코드")
        print(f"  - {item['file']}:{item['line']}: {label}")
        print(f"    코드: {item['code']}")

    if not report["runtime"] and not report["target"].startswith("container:"):
        print("\n다음 확인: 실행 중인 컨테이너를 안다면 같은 명령에 --container 컨테이너이름을 붙이세요.")
    extra_notes = [note for note in report["notes"] if not note.startswith("정적 분석은 실제 요청 도달성")]
    for note in extra_notes:
        print(f"참고: {note}")
    print("주의: 이 점검은 실제 공격 성공 여부를 확인하지 않습니다.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Node2Shell(CVE-2026-111497) 로컬 프로젝트/컨테이너 위험범위 점검",
        epilog=f"제작: {AUTHOR} | 예: python node2shell_check.py C:\\path\\to\\project",
    )
    parser.add_argument("target", nargs="?", help="검사할 프로젝트 폴더 (컨테이너만 검사할 때 생략 가능)")
    parser.add_argument("--container", metavar="NAME", help="실행 중인 본인 Docker 컨테이너에서 node --version 확인")
    parser.add_argument("--node-bin", metavar="PATH", help="지정한 로컬 Node 바이너리의 실제 버전 확인")
    parser.add_argument("--json", action="store_true", help="기계 판독용 JSON 출력")
    parser.add_argument("--no-color", action="store_true", help="색상 출력 끄기")
    args = parser.parse_args(argv)
    if not args.target and not args.container:
        parser.error("프로젝트 폴더 또는 --container를 지정하세요")
    root = None
    if args.target:
        root = resolve_project_dir(args.target)
        if root is None:
            parser.error(
                f"프로젝트 폴더를 찾지 못했습니다: {args.target} (현재 위치: {Path.cwd()}). "
                "상대 경로는 현재 위치를 기준으로 지정하세요. IP/URL은 검사할 수 없습니다"
            )
    runtime = None
    notes = ["정적 분석은 실제 요청 도달성, 컨테이너 배포 버전, 배포판 백포트를 확정하지 못합니다."]
    if args.container:
        value, error = command_version(["docker", "exec", args.container, "node", "--version"])
        if error:
            notes.append(f"컨테이너 버전 확인 실패: {error}")
        else:
            runtime = {"version": value, "status": version_status(value), "source": f"container:{args.container}"}
    elif args.node_bin:
        value, error = command_version([args.node_bin, "--version"])
        if error:
            notes.append(f"Node 바이너리 확인 실패: {error}")
        else:
            runtime = {"version": value, "status": version_status(value), "source": args.node_bin}
    versions = scan_versions(root) if root else []
    paths = scan_source(root) if root else []
    if runtime and runtime["status"] == "unsupported-or-unassessed":
        notes.append("이 Node 계열은 공식 수정 버전 비교표 밖입니다. 안전 판정이 아니며 지원되는 수정 버전으로 교체해야 합니다.")
    if runtime and runtime["status"] == "fixed" and any(item["status"] == "affected" for item in versions):
        notes.append("소스의 취약 버전 고정값과 실행 중인 수정 버전이 다릅니다. 빌드 인자/배포 구성을 확인하세요. 판정은 확인한 실행 버전을 우선합니다.")
    report = {"author": AUTHOR, "cve": "CVE-2026-111497", "target": str(root) if root else f"container:{args.container}",
              "runtime": runtime, "version_evidence": versions, "code_paths": paths,
              "assessment": assess(runtime, versions, paths), "notes": notes}
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        print_report(report, not args.no_color)
    return 0 if report["assessment"] in {"PATCHED_RUNTIME", "NO_EVIDENCE"} else 1


if __name__ == "__main__":
    sys.exit(main())
