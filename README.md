# Node2Shell checker

본 도구는 로컬 프로젝트와 선택한 실행 환경이 Node2Shell(CVE-2026-111497)의 위험 범위에 있는지 조사합니다. 공격 요청을 보내거나 취약점을 실행하지 않습니다!

## 준비

Python 3.10 이상이 필요합니다. 이 체커 저장소의 루트에서 PowerShell을 열고 다음을 실행합니다.

~~~powershell
python -m pip install -r .\requirement.txt
python .\node2shell_check.py -h
~~~

색상 출력에는 `colorama`를 사용합니다. 색상이 필요 없으면 `--no-color`를 붙입니다. 실행 중인 컨테이너의 버전을 확인할 때만 Docker Desktop이 필요합니다.

## 사용법

아래 명령은 모두 이 체커 저장소의 루트에서 실행합니다. 대상에는 검사할 Node.js 프로젝트의 실제 폴더 경로를 넣습니다. 상대 경로는 현재 PowerShell 위치를 기준으로 해석합니다.

~~~powershell
# 프로젝트 파일만 검사
python .\node2shell_check.py 'C:\path\to\node-project'

# 프로젝트 파일과 실행 중인 실습 컨테이너를 함께 검사
python .\node2shell_check.py 'C:\path\to\node-project' --container YOUR_CONTAINER

# 컨테이너의 실제 Node 버전만 확인
python .\node2shell_check.py --container YOUR_CONTAINER

# 로컬 Node 실행 파일의 버전도 확인
python .\node2shell_check.py 'C:\path\to\node-project' --node-bin node

# JSON 결과
python .\node2shell_check.py 'C:\path\to\node-project' --container YOUR_CONTAINER --json
~~~

`C:\path\to\node-project`와 `YOUR_CONTAINER`는 본인의 경로와 컨테이너 이름으로 바꾸세요. 로컬 Node2Shell 실습을 별도 저장소 `C:\Users\home\Desktop\node2shell`에 둔 경우에는 `..\node2shell\website`를 대상으로 지정할 수 있습니다. IP나 URL은 검사 대상으로 받지 않습니다. 원격 주소만으로 내부 Node 버전이나 Brotli 입력 경로를 확인할 수 없기 때문입니다.

## 출력 예시

프로젝트 파일만 검사하면 다음처럼 결과의 뜻과 근거를 보여줍니다.

~~~text
Node2Shell 점검기 | 작성자 amier_ge
결과: 취약 가능성 있음
뜻: 프로젝트 파일에서 취약 버전과 관련 코드를 찾았습니다. 실행 중인 버전은 아직 모릅니다.

찾은 근거:
  - Dockerfile.shell:1: Node 24.22.0 (수정 전 버전)
  - server.js:7: 압축된 요청 본문을 해제할 수 있는 코드

다음 확인: 실행 중인 컨테이너를 안다면 같은 명령에 --container 컨테이너이름을 붙이세요.
~~~

실제 출력에는 검사 대상 경로와 발견한 코드도 표시됩니다. 일반 출력은 쉬운 설명을 사용하고, `--json`에서는 `POTENTIAL_EXPOSURE` 같은 판정 코드를 그대로 제공합니다.

## 검사 내용

| 검사 | 확인하는 정보 |
| --- | --- |
| 버전 단서 | `.nvmrc`, `.node-version`, `package.json`의 `engines.node`, Dockerfile의 Node 이미지, Compose의 `NODE_VERSION` |
| 코드 경로 | 직접 Brotli 해제 호출, Express/body-parser 본문 파서, `fetch()` 호출 후보와 파일·줄 번호 |
| 실행 버전 | `--container`로 지정한 컨테이너의 `node --version` 또는 `--node-bin`으로 지정한 로컬 실행 파일의 버전 |

수정 버전 비교 기준은 Node.js 22.23.4, 24.22.1, 26.12.1입니다. 검사 결과는 파일명, 줄 번호, 코드 조각, 버전 단서, 실행 버전과 종합 판정을 표시합니다.

## 판정 읽기

| 판정 | 의미 |
| --- | --- |
| `HIGH_EXPOSURE` | 확인한 실행 버전이 취약 범위이고 Brotli 해제 가능 코드 경로도 발견됨 |
| `AFFECTED_RUNTIME` | 실행 버전이 취약 범위이지만 코드 경로는 발견되지 않음 |
| `POTENTIAL_EXPOSURE` | 프로젝트 파일에 취약 버전 고정값과 코드 경로가 함께 발견됨 |
| `AFFECTED_VERSION_PIN` | 취약 버전 고정값만 발견됨 |
| `PATCHED_RUNTIME` | 확인한 실행 중 Node 버전이 수정 버전임 |
| `REVIEW_RUNTIME` | 코드 경로는 있지만 실행 버전을 확인하지 못함 |
| `NO_EVIDENCE` | 검사한 파일에서 해당 단서를 찾지 못함 |

`HIGH_EXPOSURE`도 실제 요청 도달성이나 익스플로잇 성공을 증명하지 않습니다. `NO_EVIDENCE`도 안전하다는 보장이 아닙니다. 인증, 입력 통제, 배포판의 보안 수정 백포트, 실제 배포 이미지 등은 별도로 확인해야 합니다.

종료 코드는 `PATCHED_RUNTIME`과 `NO_EVIDENCE`에서 0, 추가 검토가 필요한 나머지 판정에서 1입니다. 잘못된 명령 인자는 2를 반환합니다.

작성자: **amier_ge**
