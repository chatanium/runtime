# 일반 사용자로 실행하는 GVX 모듈 런타임 - Spec Proposal

| Item | Detail |
|---|---|
| Author | Seonguk Moon |
| Created | 2026-11-21 |
| Updated | 2026-11-25 |
| Status | **Draft** / In Review / Approved |
| Reviewers | |

---

## 1. Summary

사용자는 OS와 CPU에 맞는 Chatanium 바이너리 하나를 받아 자기 계정으로 모듈을 실행합니다. Chatanium은 승인한 CPU, 메모리, PID, 네트워크, 디스크 한도를 번들에 포함한 공식 GVX `rungv`에 전달하고, GVX는 각 샌드박스에 이를 적용합니다. Chatanium은 모듈 권한, 설치 전체의 디스크 예산, 실행과 정리를 맡습니다.

## 2. Background & Motivation

[0번 프로포절](chatanium-0-self-contained-runtime.md)은 기존 Linux 설치의 명세로 남깁니다. 기존 설치는 시스템 계정과 그룹 3쌍, systemd, XFS 프로젝트 쿼터, 선할당 루프 파일을 사용합니다. 잠깐 실행해도 호스트 전체를 변경하므로 일반 사용자용 설치는 별도 형식 `portable-v2`를 사용합니다.

[현재 Chatanium 배포 핀](tools/build/release-lock.json#L3-L19)은 `v0.16.10002026110900`입니다. 이 제안의 기준은 [공식 GVX `v0.22.10002026111600`](https://github.com/gfire-sigs/gvx/releases/tag/v0.22.10002026111600), 커밋 `a90476e02630e7d35861e1da16d407e03e71e8b7`입니다. 이 버전이 제공하는 NAT 방화벽, 대역폭 제한, ext4lite 볼륨을 사용합니다. 새 전송 프로토콜이나 볼륨 할당기를 만드는 작업은 필요 없습니다. 핀 변경과 제품 통합은 구현 단계에 남습니다.

## 3. Goals & Non-Goals

### 3.1 Goals

- [ ] 일반 계정으로 설치, 실행, 업데이트, 제거. 변경 전 쓰기 경로와 최대 디스크 예산 표시
- [ ] 기존 모듈 소켓과 파일 API 유지. `NONE`과 `PUBLIC_INTERNET`, 영구 데이터와 실행별 scratch 구분
- [ ] 모듈 인증과 승인 이후에만 외부 통신 허용. 타깃이 승인한 제한을 적용할 수 없으면 기동 거부

### 3.2 Non-Goals

- [ ] 송신 NIC, 출발지 인터페이스, 호스트 라우팅 경로 고정. 게스트 볼륨별 독립 inode 쿼터
- [ ] 호스트 전체 CPU 시간, 프로세스 수, RSS 또는 물리 디스크 공간의 예약과 보장
- [ ] 호스트 계정, 시스템 서비스, 호스트 cgroup, 네트워크 네임스페이스, 방화벽 규칙, 루프 마운트 생성
- [ ] 기존 관리자 설치나 이름을 붙여 사용하던 `portable-v2/<이름>` 설치의 자동 이관 또는 삭제, 부팅 시 자동 시작, GVX 사설 포크, 다른 ISA의 에뮬레이션

불신 대상은 모듈과 외부 OCI 내용입니다. 설치 소유자 및 같은 계정으로 직접 실행한 네이티브 프로그램은 신뢰합니다.

## 4. Technical Design

### 4.1 Architecture Overview

| 주체 | 맡는 일 |
|---|---|
| Chatanium 감독자 | 번들 검증, 승인과 예산 원장, `rungv` 기동 인자 생성, 정책 적용, 자식 종료 확인 |
| 네이티브 워커 | 비공개 채널로 받은 토큰으로 고정 백엔드에 연결하고 모듈 RPC 중개. 모듈에는 토큰과 관리 핸들 미전달 |
| 인스턴스별 `rungv` | 게스트 자원 제한, NAT 소켓과 방화벽, 읽기 전용 루트와 ext4lite 마운트. 호스트 관리자 권한 없이 실행 |
| 신뢰된 게스트 브리지와 이미지 준비기 | 브리지는 게스트 저장소를 확인한 후 비루트 UID/GID로 모듈 시작. 준비기는 별도 네트워크 없는 게스트에서 이미지 검사 |

**배포 대상.** 호스트 OS와 ISA에 맞는 `rungv`와 워커, 같은 ISA의 Linux 게스트 브리지와 준비기를 한 배포물에 묶습니다. Linux amd64/arm64는 `systrap`, macOS arm64는 entitlement를 포함해 서명한 `hvf`, Windows amd64/arm64는 `whpx`를 대상으로 합니다. Windows의 WHPX 활성화와 재부팅은 설치기가 대신 수행하지 않습니다. WHPX가 없으면 원인을 표시하고 중단하며 Windows `systrap`으로 대체하지 않습니다. 공식 자산의 출처, 서명, 해시는 빌드할 때 고정합니다. 실행 중 `latest`를 다운로드하지 않으며, 네이티브 음성을 포함해 해당 타깃에서 확인한 기능만 표시합니다.

**사용자 흐름.** 사용자 계정마다 환경 하나를 씁니다. 배포물을 검증한 뒤 `serve`를 실행합니다. 설치가 없으면 초기 설정부터 진행하고, 승인이 끝나면 같은 명령에서 전경 워커를 시작합니다. 모듈을 지정하지 않으면 컨테이너를 띄우지 않고 대기합니다. `doctor`는 선택 사항이며, 설정만 하고 종료하려면 `init`을 사용합니다.

1. 사용자 데이터 폴더(Linux: XDG 데이터 경로, macOS: Application Support, Windows: LocalAppData) 아래의 `chatanium/runtime` 경로, 번들과 이미지의 출처, 최대 디스크 예산을 보여줍니다. 사용자가 `PlanDigest`를 승인하기 전에는 설치 파일을 쓰지 않습니다.
2. 승인한 위치에서 파일 생성과 배타적 잠금을 확인합니다. 처음 설치할 때 내부 식별자를 생성해 설정, 원장과 백업이 같은 설치에 속하는지 확인하는 데 씁니다. 모듈 이미지는 별도 준비 게스트에서 검사하며, 준비 중에는 모듈을 실행하지 않습니다.
3. 이미지 digest, 모듈 선언, 적용할 자원 한도와 네트워크 프로필을 보여주고 모듈별 `ReviewDigest`를 받습니다. 준비 자원을 정리하고 승인값과 결과가 일치할 때만 설치를 `READY`로 활성화합니다.

추가 이미지는 `prepare-image` → `generate-config` → `configure` 순서로 같은 승인을 받습니다. `stop`은 실행을 끝냅니다. `uninstall`은 설치된 코드만 지우고, `purge`는 삭제 범위를 다시 승인받은 뒤 설치 소유 데이터까지 지웁니다. 사용자가 다운로드한 바이너리와 공유 부모 디렉터리는 유지합니다. 삭제와 갱신에는 설치가 소유한 핸들을 사용하며 외부 경로로 이어지는 링크나 Windows 재분석 지점을 따르지 않습니다.

**게스트 연산 자원.** 기동할 때 세 값을 모두 명시합니다. CPU와 PID는 양수여야 하며 엔진이 표현할 수 없는 값은 승인 전에 거부합니다. 준비 게스트에도 별도의 유한한 예산을 적용합니다.

| 승인 필드 | GVX 기동 옵션 | 보장 범위 |
|---|---|---|
| `cpu_millicores` | `--cpus`에 1,000으로 나눈 십진수 전달 | 게스트 CFS CPU 시간 할당량. `500m`은 CPU 0.5개분의 시간이며 게스트에는 올림한 CPU 1개가 보입니다. |
| `memory_bytes` | `--memory` | 최소 6 MiB. GVX가 게스트 사용량을 주기적으로 검사하고 초과하면 종료합니다. 검사 사이 순간 초과 및 호스트 워커나 엔진 전체 RSS는 한도 밖입니다. |
| `max_pids` | `--pids-limit` | 게스트의 루트 `cgroup2`가 스레드를 포함한 전체 태스크 수를 제한합니다. Chatanium은 호스트 cgroup을 만들지 않으며 무제한을 뜻하는 `0`을 전달하지 않습니다. |

### 4.2 Data Model Changes

설치 manifest와 `supervisor.sqlite`에 새 형식 `portable-v2`를 사용합니다. 새 ID와 사용자 경로에만 생성하고 기존 `chatanium-gvx` v1/XFS 설치를 열어 갱신하지 않습니다.

| 기록 | 저장할 내용과 불변식 |
|---|---|
| 설치와 승인 | 설치 ID, 타깃, 번들 및 엔진 digest, 이미지 digest, 자원 형식 버전, `ReviewDigest`를 저장합니다. 네트워크 프로필에는 주소 계열, 제외할 주소, 승인 DNS, 게스트 송수신 한도(`net_tx_bps`, `net_rx_bps`), 유효 정책 digest를 담습니다. |
| 볼륨과 예산 | 영구 볼륨의 소유 모듈, 식별자와 이미지 경로, 실행별 scratch 식별자, 각각의 승인된 이미지 최대 바이트, 점유 상태를 기록합니다. 준비, 캐시, 로그, 메타데이터, 백업의 동시 점유도 원장에서 관리합니다. |
| 실행 저널 | 설치 세대(epoch), 인스턴스·엔진 식별자, 원하는 상태, 회수 중인 자원. 이그레스 세대는 추적하되 과거 `OPEN` 기록은 재기동 권한이 아닙니다. PID만으로 기존 자식을 채택하거나 죽이지 않습니다. |

core-v2 `ResourceLimits`의 필드와 번호를 유지합니다. `max_pids = 3`과 이를 사용하는 `audio-player`의 워커 수 검사는 그대로 둡니다. `persistent_bytes = 4`와 `scratch_bytes = 5`는 `portable-v2`에서 **각 이미지 전체의 최대 바이트**를 뜻합니다. 메타데이터를 뺀 사용자 데이터 보장량으로 해석하던 설정이나 이미지는 묵시적으로 전환하지 않습니다. 새 의미를 선언한 이미지와 한도를 함께 승인하고 `INIT`에 같은 값을 보냅니다. QoS는 감독자가 승인한 네트워크 프로필에 저장합니다. 모듈 RPC에는 GVX 관리 권한을 추가하지 않습니다.

### 4.3 Core Logic

#### 네트워크: 차단 상태에서 시작하고 승인 후 방화벽 교체

`NONE`은 `--net=none`으로 시작합니다. `PUBLIC_INTERNET` 후보는 `--net=nat --isolate-lan --nat-policy-file=deny.json`으로 시작합니다. 감독자가 소유하는 `deny.json`의 내용은 `{"egress":{"default":"deny"},"ingress":{"default":"deny"}}`입니다. 첫 제어 호출 전에도 두 방향이 모두 닫혀 있어야 합니다. 포트 공개와 동적 포트를 끄고 `--privileged=false`를 사용합니다. 모듈과 그 자식의 일반 소켓은 GVX NAT를 거치며, 송신 경로는 호스트 OS가 선택합니다.

1. **기동과 승인.** 감독자는 `--net-tx-bps`와 `--net-rx-bps`에 승인한 한도를 전달합니다. 두 값은 게스트 기준 송신과 수신 **bit/s**이며, 각 방향에서 샌드박스 전체 흐름이 한도를 공유합니다. `0`은 해당 방향의 무제한을 명시적으로 승인한 경우에만 사용합니다. `NONE`에는 두 옵션을 전달하지 않습니다.
2. **열기.** 브리지가 저장소 준비를 마치면 워커가 모듈을 인증하고 `GetManifest`를 이미지 선언과 대조한 뒤 grant를 협상합니다. 감독자는 `NONE`이면 실제 `network_mode=none`을 확인합니다. `PUBLIC_INTERNET`이면 초기 차단 정책과 유효 QoS를 확인한 뒤 승인된 정책 전체를 설치합니다. 적용 결과가 일치해야 워커가 `STAGE_INIT`을 보냅니다.
3. **철회.** 감독자는 인스턴스별 변경을 직렬화하고 해당 승인 세대를 닫은 뒤 양방향 차단 정책을 다시 설치합니다. GVX는 금지된 기존 TCP, UDP, DNS 흐름에 취소를 전달합니다. 교체 응답은 소켓 종료 확인이 아니며 이미 보낸 바이트도 회수할 수 없습니다. 철회, 워커 종료, 제어 연결 단절, 적용 결과 불명 시 해당 엔진을 종료하고 실제 종료를 확인합니다. 다시 허용하려면 새 인스턴스와 새 승인 세대가 필요합니다.

**`PUBLIC_INTERNET` 규칙 순서.** NAT 방화벽은 처음 일치한 L3/L4 규칙을 적용합니다. `ingress`는 기본 거부하고, 허용된 게스트 발신 흐름의 응답만 돌아옵니다. `egress`도 기본 거부하며 다음 순서로 예외를 만듭니다.

1. GVX 가상 DNS `10.0.2.3/32`의 TCP/UDP 53만 허용합니다. `--host-dns`에는 승인한 공인 DNS의 숫자 주소만 지정합니다. GVX는 게스트가 요청한 주소와 실제 상위 DNS에 보내는 각 시도를 모두 검사합니다.
2. 알려진 호스트 주소, 가상 게이트웨이, 내부망과 다른 인스턴스, 운영자가 등록한 공인 NAT 별칭, 사설 및 특수 목적 대역(링크 로컬과 메타데이터 포함)을 차단합니다. 주소는 GVX의 IPv4-mapped 정규화에 맞춰 변환합니다.
3. 승인한 상위 DNS로 가는 TCP/UDP 53을 허용하고 나머지 53과 UDP 3544를 차단합니다. 마지막에 승인한 주소 계열의 공인 TCP/UDP만 허용합니다. DNS 응답 자체가 접속을 허가하지는 않습니다.

v0.22의 기본 NAT 게스트 주소와 기본 경로는 IPv4입니다. 정책 문법이 IPv6를 받아도 실제 경로와 DNS를 확인한 타깃에서만 dual-stack을 승인합니다. 그 밖의 타깃은 dual-stack 요청을 거부합니다. 이 프로필이 판별하는 값은 IP, 프로토콜, 포트입니다. VPN 경로나 공인 HTTPS 프록시 뒤의 최종 목적지까지 보장하지 않습니다.

#### 디스크: 영구 이미지 하나와 실행별 scratch 하나

`persistent_bytes`와 `scratch_bytes`를 각 ext4lite 마운트의 `size=`로 전달합니다. 허용 범위는 **16 MiB부터 64 TiB까지, 16 MiB의 정수배**입니다. `0`, 누락, 범위 밖 값, 나누어떨어지지 않는 값은 승인 전에 거부합니다. 예를 들어 `size=64m`은 파일시스템의 저널과 메타데이터를 포함한 이미지 최대 길이입니다. 게스트 파일에 64 MiB를 쓸 수 있다는 약속은 아닙니다.

새 이미지는 16 MiB 그룹 하나에서 시작해 공간이 필요할 때 그룹 단위로 자랍니다. GVX는 전체 상한을 미리 예약하지 않습니다. 호스트가 지원하면 새 그룹의 공간을 할당하고, 파일시스템에 따라 실제 디스크 점유량은 달라집니다. 상한에 닿기 전에도 호스트 디스크가 차면 쓰기가 실패합니다.

**영구 데이터.** 모듈마다 설치 소유 경로 하나를 배정하고 `/var/lib/flexmodule/data`에 연결합니다. 새 이미지에서는 브리지가 데이터 디렉터리의 소유자를 승인된 게스트 UID/GID로 설정합니다. 기존 이미지는 소유권을 확인하고 불일치하면 중단합니다. 쓰기는 한 인스턴스만 허용합니다. `size`는 이미지를 열 때만 적용되므로 매 `run`에 승인값을 다시 전달합니다. 기존 이미지가 상한보다 크면 자르지 않고 기동을 거부합니다. 비정상 종료 후의 저널 재생은 GVX가 맡습니다.

**임시 데이터.** 인스턴스마다 `ephemeral`을 한 번만 지정합니다. `src`와 `readonly`는 함께 지정할 수 없습니다. 마지막 backing 핸들이 닫히면 임시 이미지를 회수하고, 다음 실행은 빈 scratch로 시작합니다. `ephemeral` 볼륨을 쓰는 실행 전체는 GVX 체크포인트를 사용할 수 없습니다. `stop` 후 새로 기동하는 절차와 영구 데이터 백업은 그대로 가능합니다.

예를 들어 설치 소유 데이터 디렉터리를 기준으로 다음 두 마운트를 `rungv run`에 전달합니다. 루트는 `--read-only`, 호스트 접근은 `--lockdown=true`로 유지하고 호스트 디렉터리를 모듈의 쓰기 경로로 바인드하지 않습니다.

```text
--mount type=volume,src=./volumes/m42.ext4,dst=/var/lib/flexmodule/data,driver=ext4lite,size=64m
--mount type=volume,dst=/var/lib/flexmodule/scratch,driver=ext4lite,size=32m,ephemeral
```

**`/tmp`와 scratch가 한도를 공유하는 방법.** `ephemeral`을 두 번 쓰면 서로 다른 이미지가 생깁니다. Chatanium은 게스트에 마운트한 이미지 하나에 `tmp`와 `work` 디렉터리를 나란히 만듭니다. 신뢰된 브리지가 모듈을 시작하기 전에 원본 디렉터리 FD를 링크를 따르지 않고 열어 둡니다. 먼저 `tmp`를 `/tmp`에, 그다음 `work`를 `/var/lib/flexmodule/scratch`에 게스트 `MS_BIND`로 연결합니다. 최종 경로의 `(st_dev, st_ino)`를 각각 원본 FD와 대조합니다. 두 경로의 쓰기는 한 상한에 합산되고, scratch를 비워도 `/tmp`의 모듈 소켓은 남습니다.

게스트 진입점은 번들에 포함한 읽기 전용 브리지로 고정합니다. 이 브리지만 게스트 `0:0`과 게스트의 `CAP_SYS_ADMIN`으로 바인드합니다. 두 디렉터리에 승인된 비루트 UID/GID와 모드 `0700`을 적용하고 `ROOTS_READY`를 보냅니다. `ROOTS_COMMIT` 뒤 모든 스레드의 권한을 내리고 초기화 FD를 닫은 후 모듈을 시작합니다. `--privileged=false`에서 이 구성을 확인하지 못한 타깃은 기동을 거부합니다. `/dev/shm`을 제공할 때는 승인된 크기의 메모리 파일시스템으로 제한하고 디스크 예산과 구분합니다.

**설치 전체 예산.** 감독자는 볼륨 생성이나 실행 전에 SQLite 트랜잭션으로 점유를 잡습니다. 보존 중인 영구 이미지 상한과 활성 또는 회수 중인 scratch 상한에 이미지 준비, 캐시, 회전 로그, 메타데이터, 백업이 동시에 사용할 최대 바이트를 더합니다. 합계가 승인 예산을 넘으면 생성 전에 거부합니다. 이 원장은 호스트 디스크 공간을 예약하지 않습니다.

재기동할 때 소유 기록, 이미지 식별자, 잠금과 승인 상한을 확인합니다. scratch 점유는 이전 엔진과 backing 핸들이 종료되고 생성 도중 남은 임시 파일까지 회수한 뒤 반납합니다. 결과가 불명확하면 `CLEANUP_PENDING`을 유지합니다. 영구 점유는 `stop`과 `uninstall` 후에도 보존하며 승인된 삭제에서만 반납합니다.

#### 외부 이미지 준비와 캐시 게시

감독자는 승인된 레지스트리, 저장소, digest 또는 사용자가 지정한 오프라인 입력에서 원본 바이트를 받습니다. 번들에 든 신뢰된 준비기를 `--net=none` 게스트에서 실행해 OCI 자료를 해석하고 같은 버전의 Linux `rungv load`로 오프라인 컴파일합니다. 준비기는 필요한 자료의 종류와 digest만 요청할 수 있습니다. 레지스트리 자격 증명이나 임의의 호스트 경로는 넘기지 않습니다.

입력, 압축 해제 결과, 출력의 바이트와 항목 수, 처리 시간을 제한합니다. 감독자는 길이가 제한된 스트림으로 결과를 받고 모든 writer가 끝난 뒤 선언, ISA, digest, 형식을 확인해 읽기 전용 캐시 세대를 게시합니다. 모듈은 `--pull=never`로 이 세대만 사용합니다.

**출시 조건:** v0.22의 `Sandbox.New`는 `initOCILayers`를 호출한 뒤 `hostlockdown.Apply`를 호출합니다. digest 일치와 `--pull=never`만으로 비신뢰 캐시의 파싱까지 격리했다고 볼 수 없습니다. 게시된 형식 중 호스트가 lockdown 전에 읽는 부분을 식별하고, 비신뢰 내용의 첫 해석 전에 일반 사용자 권한으로 접근을 제한하는 경로를 타깃별로 확인해야 합니다. 이 조건을 만족하지 못하면 외부 이미지를 받는 모듈 경로를 열지 않습니다.

#### 감독자 종료와 업데이트

사용자용 관리 IPC는 소유자 전용 로컬 소켓 또는 Windows named pipe를 사용합니다. 엔진용 `gvx-ctrl/2`는 `--control-socket`으로 별도로 엽니다. Linux와 macOS는 사용자 전용 디렉터리의 Unix 소켓과 peer UID를, Windows는 로컬 GVX 소켓과 사용자 ACL로 보호한 실행별 토큰을 사용합니다. `--control-disable`로 불필요한 기능을 끄고 소켓과 토큰을 게스트 마운트 밖에 둡니다. 모듈 stdio의 `CTGVXIPC1`과 AutoMTLS RPC에는 이 핸들을 전달하지 않습니다.

`stop`은 원하는 상태 `STOPPED`를 먼저 기록합니다. 제어 연결이 끊겼다는 사실만으로 `rungv` 종료를 확정하지 않습니다. Unix에서는 감독자만 쓰기 끝을 보유한 수명 채널을 감시하는 실행 관리자가 EOF에서 자식을 종료하고, Windows에서는 자식 이탈을 막은 종료 연동 Job을 사용합니다. 워커, 엔진, 보조 자식까지 끝났는지 확인합니다. 확인 전에는 실행 상태 `UNKNOWN`과 `CLEANUP_PENDING`을 유지하며 저장소와 점유를 재사용하지 않습니다.

`update`는 모든 writer를 멈춘 뒤 SQLite, 설정, 참조 중인 영구 이미지를 함께 백업합니다. 새 위치의 논리 길이, 내용 해시, 동기화를 확인한 뒤 전환합니다. 희소 구간을 보존할 수 없는 복사는 이미지 논리 길이까지 백업 예산에 포함합니다. 공간이나 검증이 부족하면 기존 세대를 유지합니다. v1의 중지, 복구, 삭제는 기존 바이너리가 맡습니다.

## 5. API Design

### 5-1. New / Modified

아래 함수는 Chatanium 내부 어댑터입니다. 모듈의 공개 RPC는 바꾸지 않습니다. 관리 CLI는 환경 이름을 받지 않고 사용자 데이터 폴더의 설치 하나만 엽니다. 모듈과 백업을 지정할 때는 각각 `--module-id`와 `--backup-id`를 사용합니다.

```go
// PlanRun validates the approved limits and renders fixed arguments before any guest code runs.
func PlanRun(target Target, grant ApprovedGrant, volumes VolumeLease) (RunPlan, error)

// SetEgress serializes changes for this live instance; revocation never authorizes a reopen.
func (a *GVXAdapter) SetEgress(ctx context.Context, instanceID string, policy EgressPolicy) error
```

`PlanRun`은 예산을 잡은 볼륨에 대해서만 인자를 만들고, 승인하지 않은 `0`이나 표현할 수 없는 값을 거부합니다. `SetEgress`는 호출자의 설치, 세대, 인스턴스를 대조한 후 해당 엔진에서만 동작합니다. 아래 이름은 v0.22에 실제로 있는 제어 인터페이스입니다.

| GVX 인터페이스 | 감독자의 사용 방식 |
|---|---|
| `HELLO`, `sandbox.inspect`, `mount.list` | 새 제어 세션의 `sandbox_id`, 기능과 권한을 확인합니다. 엔진, lockdown, 게스트 자원값, 마운트 대상과 쓰기 모드를 승인 계획과 대조합니다. `mount.list`는 볼륨 `size`나 `ephemeral`을 반환하지 않으므로 이 값은 검증된 엔진에 전달한 기동 인자와 마운트 성공으로 확인합니다. |
| `net.policy_set`, `net.policy_get` | NAT의 `net.policy.write`와 `net.policy.read` 권한으로 `{"policy": ...}`에 담은 전체 정책을 교체하고 설치 결과를 대조합니다. `null`은 차단 확인으로 취급하지 않습니다. |
| `resource.update` | GVX는 CPU, 메모리, PID 및 NAT 송수신 한도의 실시간 변경을 지원합니다. 감독자는 해당 세대에서 승인한 값만 적용하고 유효값을 비교합니다. QoS에는 `net_qos` 기능과 `resource.network` 권한이 필요합니다. 방화벽 교체는 QoS를 바꾸지 않습니다. |
| `lifecycle.stop` | 게스트 종료를 요청합니다. 응답이 없으면 감독자가 소유한 프로세스 핸들로 종료하고 실제 자식 종료를 기다립니다. |

### 5-2. Error Handling

| 오류 또는 관측값 | 동작 |
|---|---|
| `UNSUPPORTED_TARGET` / `ENGINE_CAPABILITY_MISSING` | 표시된 백엔드, 자원 제한, 저장소 또는 수명 조건이 빠지면 해당 타깃의 기동을 거부합니다. NAT 정책이나 요청한 QoS만 지원하지 않는 경우 `PUBLIC_INTERNET` 요청을 거부하며 `NONE`으로 몰래 낮추지 않습니다. |
| `APPROVAL_MISMATCH` / `EGRESS_REVOKED` | 승인이나 실행 세대가 다르면 열기를 거부합니다. 이미 권한을 부여했거나 적용 결과가 불명확하면 해당 인스턴스를 종료하고 이전 허용 정책을 복원하지 않습니다. |
| `BUDGET_EXCEEDED` / `VOLUME_BUSY` | 볼륨 생성·동시 기동·백업 전에 거부합니다. 기존 영구 데이터와 점유를 유지합니다. |
| 게스트 `ENOSPC` | ext4lite 이미지가 상한에 도달하거나 호스트 공간이 먼저 고갈될 때 발생할 수 있습니다. 쓰기 또는 지연 쓰기의 동기화가 실패할 수 있으며, 같은 errno만으로 원인을 구분하지 않습니다. |
| `CLEANUP_PENDING` / `LEGACY_INSTALLATION` | 종료·회수를 입증하지 못하면 점유를 유지합니다. 구 설치라면 변경 전에 중단하고 호환되는 기존 런처를 안내합니다. |

## 6. Implementation Plan

### 6-1. Milestones

| Phase | 독립 작업과 완료 조건 | Estimated Duration | Owner |
|---|---|---|---|
| 1. 설치와 감독 | 타깃별 v0.22 자산 고정, 사용자 경로, 인증된 제어 연결, 자식 수명 관리. 감독자가 사라져도 자식이 남지 않고 v1은 그대로여야 합니다. | 미산정 | Chatanium 런타임 |
| 2. 연산 자원과 네트워크 | 기존 grant를 CPU, RAM, PID 옵션과 deny-first NAT 정책으로 변환합니다. 승인 직전까지 외부 소켓이 막히고 승인된 방화벽과 송수신 한도가 적용되며, 철회 후 종료를 확인해야 합니다. | 미산정 | Chatanium 런타임 |
| 3. 볼륨과 예산 | 기동 인자, 게스트 디렉터리 준비, 점유 원장을 연결합니다. 디스크가 차면 해당 볼륨의 쓰기가 실패하고, 다음 기동에서 영구 데이터만 남아야 합니다. | 미산정 | Chatanium 저장소 |
| 4. 이미지와 모듈 호환 | 격리된 이미지 준비, 읽기 전용 게시, 자원 형식 승인. 외부 입력을 보호된 경로에서 처리하고 기존 PID 필드를 포함한 grant로 비루트 모듈을 실행해야 합니다. | 미산정 | Chatanium 배포 / SDK |

각 작업은 위 기동 인자, 승인 필드, 원장 상태를 기준으로 독립적으로 구현합니다. 출하 후보 타깃에서는 일반 계정으로 `init` → 이미지 준비 → 모듈 기동 → 종료 → 제거를 한 번 연결해 확인합니다. 실패한 단계만 따로 조사합니다.

### 6-2. Dependencies

공통 전제는 서명을 확인한 타깃별 GVX, 사용할 수 있는 백엔드, 인증된 관리 IPC, 게스트 자원 제한과 볼륨 잠금입니다. Chatanium은 기존 SQLite 원장과 모듈 RPC를 사용하고, 비신뢰 이미지 처리와 부모 종료 시 자식 회수를 타깃별로 확인합니다.

`PUBLIC_INTERNET`에는 GVX NAT 정책 읽기와 쓰기 권한, 승인한 주소 계열 및 요청한 QoS가 추가로 필요합니다. `NONE`에는 NAT 기능이 필요 없습니다. Linux의 호스트 네트워크 도구, XFS 관리 도구, systemd, 별도 GVX 데몬은 `portable-v2` 설치 요건에서 제외합니다.

## 7. References

- Chatanium: [현재 Linux 기동 인자](internal/host/gvx_platform_linux.go#L357-L392), [승인에서 `STAGE_INIT`까지](internal/runtime/manager.go#L338-L374), [특수 목적 주소 목록](internal/host/network_policy.go#L75-L92)
- 모듈: [core-v2 자원 필드](proto/core-v2/core.proto#L63-L84), [게스트 저장소 확인과 권한 전환](internal/gvxipc/bridge_linux.go#L187-L224), [`audio-player`의 한도 검사](modules/audio-player/config.go#L78-L85)
- GVX 실행: [대상 OS와 ISA](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/README.md), [CPU, RAM, PID](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/docs/cli.md#L279-L289), [OCI 초기화와 lockdown 순서](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/gvx/sandbox.go#L237-L279)
- GVX 네트워크: [NAT 대역폭, 방화벽과 DNS](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/docs/cli.md#L409-L473), [기본 IPv4 경로](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/netbackend/nat_forwarder.go#L447-L492), [`gvx-ctrl/2` 인증과 RPC](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/docs/control-protocol.md#L56-L150), [정책 교체와 연결 취소](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/netbackend/nat_policy.go#L576-L596)
- GVX 저장소: [볼륨 옵션과 체크포인트](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/docs/cli.md#L241-L249), [그룹 확장과 호스트 할당](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/docs/architecture.md#L640-L672), [게스트 마운트 순서](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/gvx/boot_vfs.go#L391-L500), [게스트 바인드와 권한](https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/sentry/syscalls/linux/sys_mount.go#L26-L113)
- 호스트: IANA 특수 목적 주소 [IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/), [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/), Microsoft [Job 수명](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects#managing-job-objects)
