# BloatwareGuard 設計ドキュメント

## 概要
Windows 11が自動的に再インストールしてくるメーカー/マイクロソフトの不要アプリ（bloatware）を
常駐型サービスで自動検知・自動削除・再インストール防止を行うツール。

## アーキテクチャ

```
┌─────────────────────────────────────────────────────┐
│                BloatwareGuard Service                │
├─────────────────────────────────────────────────────┤
│  Main Loop (every N seconds)                        │
│    ├─ Scan & Remove AppxPackages (blacklist match)  │
│    ├─ Scan & Remove ProvisionedPackages             │
│    ├─ Re-apply Registry Policies (idempotent)       │
│    └─ Disable OEM Scheduled Tasks                   │
├─────────────────────────────────────────────────────┤
│  Prevention Layers (Registry)                       │
│    ├─ DisableWindowsConsumerFeatures = 1            │
│    ├─ DisableSoftLanding = 1                        │
│    ├─ DisableCloudOptimizedContent = 1              │
│    ├─ PreventDeviceMetadataFromNetwork = 1          │
│    ├─ SilentInstalledAppsEnabled = 0                │
│    └─ SystemPaneSuggestionsEnabled = 0              │
├─────────────────────────────────────────────────────┤
│  Config: config.json (blacklist + intervals)        │
│  Log: Windows Event Log + file                      │
└─────────────────────────────────────────────────────┘
```

## 再インストール経路と対策

| 経路 | 対策 | レイヤー |
|------|------|----------|
| AppxPackage (インストール済み) | Remove-AppxPackage | RemoveAppxPackages |
| ProvisionedPackage (プロビジョニング) | Remove-AppxProvisionedPackage | RemoveAppxPackages |
| Consumer Experiences (おすすめアプリ) | DisableWindowsConsumerFeatures=1 | DisableConsumerExperiences |
| Cloud Content (ストア提案) | DisableSoftLanding=1 | DisableCloudContent |
| Device Metadata (companion app自動DL) | PreventDeviceMetadataFromNetwork=1 | PreventDeviceMetadata |
| OEM Scheduled Tasks | schtasks /DISABLE | DisableOemScheduledTasks |
| Silent App Install | SilentInstalledAppsEnabled=0 | BlockProvisioning |

## ブラックリスト方式
- config.json の `Blacklist` にパッケージ名の**部分一致**パターンを列挙
- `Microsoft.Xbox` を書けば `Microsoft.Xbox.GamingOverlay` 等も対象
- 部分一致なので、OEM名を書けばそのメーカー全アプリが対象にできる

## インストール方法
1. `BloatwareGuard.exe install` (管理者権限で実行 → sc.exe create)
2. `sc start BloatwareGuard` で起動
3. Windows起動時自動開始

## コマンド
- `BloatwareGuard.exe` — サービスとして起動 (SCMから呼ばれる)
- `BloatwareGuard.exe scan` — 1回だけスキャンして終了
- `BloatwareGuard.exe install` — Windowsサービスに登録
- `BloatwareGuard.exe uninstall` — サービスから削除
- `BloatwareGuard.exe status` — サービス状態確認

## 注意
- 管理者権限必須 (app.manifest で requireAdministrator)
- Windows Update 後にレジストリ設定がリセットされる可能性があるが、
  サービスが定期スキャンで再適用するため恒久性がある
- Microsoft Edge や Copilot もブラックリストに入れられるが、
  システム機能への影響を理解した上で有効化すること
