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
│    ├─ SystemPaneSuggestionsEnabled = 0              │
│    ├─ CDM killswitches ×18 (all HKU user hives +    │
│    │   Default profile — service runs as SYSTEM)    │
│    ├─ TurnOffWindowsCopilot / DisableAIDataAnalysis │
│    │   / AllowRecallEnablement / DisableClickToDo   │
│    ├─ AllowNewsAndInterests = 0 (Widgets)           │
│    ├─ DisableSearchBoxSuggestions = 1 (Bing検索)    │
│    ├─ Deprovisioned markers (feature update耐性)    │
│    └─ RemoveDefaultStorePackages (25H2 policy)      │
├─────────────────────────────────────────────────────┤
│  Config: config.json (blacklist + intervals)        │
│  Log: Windows Event Log + file                      │
└─────────────────────────────────────────────────────┘
```

## 再インストール経路と対策

| 経路 | 対策 | レイヤー |
|------|------|----------|
| AppxPackage (インストール済み・全ユーザー) | Remove-AppxPackage (-AllUsers) | RemoveAppxPackages |
| ProvisionedPackage (プロビジョニング) | Remove-AppxProvisionedPackage | RemoveProvisionedPackages |
| Consumer Experiences (おすすめアプリ) | DisableWindowsConsumerFeatures=1 | DisableConsumerExperiences |
| Cloud Content (ストア提案) | DisableSoftLanding=1 | DisableCloudContent |
| Device Metadata (companion app自動DL) | PreventDeviceMetadataFromNetwork=1 | PreventDeviceMetadata |
| OEM Scheduled Tasks | schtasks /DISABLE | DisableOemScheduledTasks |
| Silent App Install / 提案コンテンツ | CDM killswitches ×18 (全ユーザーハイブ + Default profile) | HardenContentDelivery |
| Feature Update での再プロビジョニング | Deprovisioned\<family> マーカーキー | MarkDeprovisioned |
| 新規ユーザーへの既定アプリ配布 (25H2) | RemoveDefaultStorePackages\<family> RemovePackage=1 | RemoveDefaultStorePackages |
| Copilot / Recall / Click to Do | TurnOffWindowsCopilot=1, DisableAIDataAnalysis=1 等 | DisableAiFeatures |
| Widgets (ニュース/天気ボード) | AllowNewsAndInterests=0 | DisableWidgets |
| Start検索の Bing ウェブ提案 | DisableSearchBoxSuggestions=1 | DisableSearchSuggestions |
| Microsoft テレメトリ/CEIP タスク | schtasks /DISABLE (exact path list) | DisableTelemetryTasks |
| テレメトリ/プライバシーポリシー | DataCollection/ActivityFeed/AdID 等の ADMX ポリシー | DisableTelemetryPolicies |
| Edge の余計な機能 (sidebar/startup boost/Spotlight) | HKLM\Policies\Microsoft\Edge DWORDs | HardenEdgePolicies |
| Win32 (MSI/EXE) ブロートウェア | Uninstall ハイブ走査 + サイレントアンインストールのみ | RemoveWin32Bloatware |
| OEM サービス (自動起動) | sc.exe stop + start= disabled | DisableOemServices |
| スタートアップ登録 (Run/RunOnce) | 全ハイブで該当値を削除 | CleanStartupEntries |

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
