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
│    ├─ CDM SubscribedContent/* = 0 (all hives)       │
│    ├─ TurnOffWindowsCopilot = 1 (HKLM+hives)        │
│    ├─ WindowsAI: DisableAIDataAnalysis = 1 等       │
│    ├─ DisableSearchBoxSuggestions = 1 (all hives)   │
│    ├─ Dsh: AllowNewsAndInterests = 0 + TaskbarDa=0  │
│    ├─ AllowTelemetry=0 + DiagTrack 停止 (全ハイブ)   │
│    ├─ GameDVR: AllowGameDVR=0 + GameDVR_Enabled=0   │
│    └─ DeliveryOptimization: DODownloadMode=0        │
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
| 各種サジェスト/広告面 (Start/設定/ロック画面/トースト) | SubscribedContent-*=0, Start_IrisRecommendations=0, ShowSyncProviderNotifications=0 等 — 全ユーザーハイブ+Defaultテンプレート | BlockProvisioning |
| Copilot | TurnOffWindowsCopilot=1 (HKLM+全ハイブ) | DisableCopilot |
| Recall/AI スナップショット | DisableAIDataAnalysis=1, TurnOffSavingSnapshots=1, AllowRecallEnablement=0 + Disable-WindowsOptionalFeature | DisableRecall |
| Bing/検索サジェスト | DisableSearchBoxSuggestions=1, BingSearchEnabled=0 (全ハイブ) | DisableSearchSuggestions |
| ウィジェット/ニュース | AllowNewsAndInterests=0, EnableFeeds=0, TaskbarDa=0 | DisableWidgets |
| テレメトリ (診断データ/広告ID/フィードバック/アクティビティ履歴/Edge) | AllowTelemetry=0, DiagTrack サービス停止, AdvertisingInfo Enabled=0, TailoredExperiencesWithDiagnosticDataEnabled=0, Start_TrackProgs=0, PublishUserActivities=0 等 — 全ハイブ | DisableTelemetry |
| GameDVR (バックグラウンド録画) | AllowGameDVR=0 (HKLM), GameDVR_Enabled=0, AppCaptureEnabled=0 (全ハイブ) | DisableGameDvr |
| Delivery Optimization (P2P 更新共有) | DODownloadMode=0 (HKLM+全ハイブ+S-1-5-20) | DisableDeliveryOptimization |
| Click to Do (AI アクション) | WindowsAI DisableClickToDo=1 (HKLM+全ハイブ) + WSAIFabricSvc 手動起動化 | DisableRecall |

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
- `BloatwareGuard.exe dry-run` — 変更なしで削除対象を表示
- `BloatwareGuard.exe --service-dry-run` — サービスモード＋強制dry-run（監視のみ）
- `BloatwareGuard.exe restore` — 削除台帳（removed-packages.jsonl）からstagedパッケージを再登録
- `BloatwareGuard.exe install` — Windowsサービスに登録
- `BloatwareGuard.exe uninstall` — サービスから削除
- `BloatwareGuard.exe status` — サービス状態確認

## 注意
- 管理者権限必須 (app.manifest で requireAdministrator)
- Windows Update 後にレジストリ設定がリセットされる可能性があるが、
  サービスが定期スキャンで再適用するため恒久性がある
- Microsoft Edge や Copilot もブラックリストに入れられるが、
  システム機能への影響を理解した上で有効化すること
