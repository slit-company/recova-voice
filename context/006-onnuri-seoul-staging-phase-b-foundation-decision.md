# 006 — Onnuri Seoul Phase B foundation: offline-only source contract

- 작성일: 2026-07-14
- 상태: `open-confirmations-pending`
- 기준: Phase B approved plan (`b69763fe2c1e5b70da3f743adac687e1779374b76abdc6971898a7025cb2cb98`)

## 배경

Recova의 자체 한국 전화 인프라 방향은 유지되지만, Phase B는 아직 클라우드 실행
권한이나 운영 준비 상태를 의미하지 않는다. 이 단계에서 허용된 작업은 고립된
로컬 worktree 안의 Terraform 소스, 정적 정책, 무네트워크 검증 도구, 문서뿐이다.
`slit`은 offline IaC 소스 소유자/승인자일 뿐 cloud runner, deployer, cloud owner가
아니다.

## 조사 근거

승인된 Phase B 계획은 provider registry/DNS/download, remote backend, GCS,
`gcloud`, console, API/IAM/resource/billing, credential, SIP/RTP 및 모든 traffic을
명시적으로 차단한다. `terraform init -backend=false`도 provider 설치를 유발할 수
있으므로, 미리 존재하는 local mirror, checksum 검사, scrubbed environment,
macOS `sandbox-exec` network deny가 모두 있어야만 로컬 Terraform 검사가 가능하다.
어느 하나라도 없으면 download나 fallback 없이 fail closed 한다.

## 결정

현재 소스가 표현하는 미래 그래프는 다음 네 리소스로 고정한다.

1. auto subnetworks 없는 custom VPC 하나: `recova-onnuri-phase-b-vpc`.
2. `asia-northeast3`의 IPv4-only subnet 하나:
   `recova-onnuri-phase-b-subnet-seoul`; RFC1918 `/24` CIDR은 미래 G0 승인값이다.
3. priority 65534, `0.0.0.0/0` source의 targetless all-protocol ingress deny 하나.
4. priority 65534, `0.0.0.0/0` destination의 targetless all-protocol egress deny 하나.

이는 design-only no-traffic 그래프다. SIP/RTP allow, Secret Manager, workload,
endpoint, attachment, route/router/NAT, sink, Scheduler, metric/alert, output,
module, data source, provisioner, 추가 provider나 traffic enablement는 포함하지
않는다. Phase A fixture의 SIP literal은 Phase B input/state/resource/evidence가
아니며 권위를 갖지 않는다.

## 열린 질문

다음은 모두 **Waiting/pending** 이며 이 문서나 소스가 해결하지 않는다.

- cloud runner/deployer와 delegated authorization
- region/CIDR/quota/org policy/collision baseline
- dedicated state bucket/prefix/location, UBA/PAP, versioning, encryption,
  lifecycle, lock, recovery
- state/evidence security, ancestor IAM/Deny/PAB, Secret defer
- auditor/read role, audit retention/readers/redaction/escalation
- finite KRW estimate, manual stop threshold, budget latency
- supplier/proof/tenant/currentness, Phase C, public, production

KRW 10 budget은 알림일 뿐 상한이 아니다. 위 확인은 독립적인 cloud owner가
완료하고, 새 Architect/Critic 검토와 명시적 remote authorization이 있어야만
원격 실행 제안을 검토할 수 있다.
