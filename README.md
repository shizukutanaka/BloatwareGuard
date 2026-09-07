# BloatwareGuard

**Windows 11のbloatware（不要アプリ）を自動検知・自動削除・再インストール防止する常駐型ツール。**

Windows Update後や新規ユーザー作成時に勝手に戻ってくる Microsoft Xbox, Solitaire, Clipchamp, McAfee, Spotify, Netflix などの不要アプリを、ブラックリスト方式で永久にブロックします。

## 機能

- **自動スキャン & 削除**: 定期スキャンでブラックリストに該当する AppxPackage を自動削除
- **プロビジョニングパッケージ削除**: 新規ユーザー作成時の再展開を防止
- **レジストリ防止レイヤー**: Consumer Experiences, Cloud Content, Device Metadata を無効化
- **OEM スケジュールタスク無効化**: メーカー製の再インストールタスクを無効化
- **Windows Update耐性**: レジストリ設定がリセットされても定期スキャンで自動復元

## 必要条件

- Windows 11 (10でも動作可能)
- Python 3.10+
- **管理者権限**（必須）

## クイックスタート

```powershell
# 管理者権限のPowerShellで実行
git clone https://github.com/yourusername/BloatwareGuard.git
cd BloatwareGuard

# 1回だけスキャン（テスト）
python bloatware_guard.py --scan

# 常駐モードで起動（5分ごとに自動スキャン）
python bloatware_guard.py

# Windowsサービスとして登録（自動起動）
python bloatware_guard.py --install
sc start BloatwareGuard
```

## 設定

`config.json` を編集して動作をカスタマイズ：

```json
{
  "ScanIntervalSeconds": 300,
  "Blacklist": [
    "Microsoft.Xbox",
    "Microsoft.GamingApp",
    "McAfee",
    "Netflix"
  ],
  "Prevention": {
    "RemoveAppxPackages": true,
    "DisableConsumerExperiences": true,
    "DisableCloudContent": true,
    "PreventDeviceMetadata": true,
    "DisableOemScheduledTasks": true,
    "BlockProvisioning": true
  }
}
```

### ブラックリストの仕様

- **部分一致**: `"Microsoft.Xbox"` を指定すると `Microsoft.Xbox.GamingOverlay`, `Microsoft.Xbox.TCUI` 等も対象
- 大文字小文字を区別しない
- OEMメーカー名（`"Dell"`, `"HPInc"`, `"Lenovo"` 等）を追加可能

### 防止レイヤー

| レイヤー | 効果 |
|----------|------|
| `RemoveAppxPackages` | インストール済みAppxPackage + プロビジョニングパッケージを削除 |
| `DisableConsumerExperiences` | Microsoft Storeのおすすめアプリ自動ダウンロードを無効化 |
| `DisableCloudContent` | スタートメニューの提案・クラウドコンテンツを無効化 |
| `PreventDeviceMetadata` | ハードウェア接続時のcompanion app自動ダウンロードを防止 |
| `DisableOemScheduledTasks` | メーカー製再インストール用スケジュールタスクを無効化 |
| `BlockProvisioning` | サイレントアプリインストール・提案を無効化 |

## コマンド

| コマンド | 説明 |
|----------|------|
| `python bloatware_guard.py` | 常駐モード（定期スキャンループ） |
| `python bloatware_guard.py --scan` | 1回だけスキャンして終了 |
| `python bloatware_guard.py --install` | Windowsサービスとして登録 |
| `python bloatware_guard.py --uninstall` | Windowsサービスから削除 |
| `python bloatware_guard.py --status` | サービス状態確認 |
| `python bloatware_guard.py --config path/to/config.json` | 設定ファイル指定 |

## ログ

- **ファイル**: `%PROGRAMDATA%\BloatwareGuard\bloatware-guard.log`
- **Windowsイベントログ**: `Application` → Source `BloatwareGuard`

## アーキテクチャ

```
┌─────────────────────────────────────────────────┐
│              BloatwareGuard Service              │
├─────────────────────────────────────────────────┤
│  Main Loop (every N seconds)                    │
│    ├─ Scan & Remove AppxPackages                │
│    ├─ Scan & Remove ProvisionedPackages         │
│    ├─ Re-apply Registry Policies (idempotent)   │
│    └─ Disable OEM Scheduled Tasks               │
├─────────────────────────────────────────────────┤
│  Prevention Layers (Registry)                   │
│    ├─ DisableWindowsConsumerFeatures = 1        │
│    ├─ DisableSoftLanding = 1                    │
│    ├─ PreventDeviceMetadataFromNetwork = 1      │
│    └─ SilentInstalledAppsEnabled = 0            │
└─────────────────────────────────────────────────┘
```

## よくある質問

**Q: 消したアプリが復活する？**
A: 本ツールは定期スキャンでレジストリ設定を再適用するので、Windows Update後も恒久的に防止されます。

**Q: システムに必要なアプリまで消される？**
A: ブラックリスト方式なので、リストに書いたものだけが削除対象です。デフォルトリストも安全なものだけにしています。

**Q: EdgeやCopilotも消せる？**
A: ブラックリストに `Microsoft.MicrosoftEdge.Stable` や `Microsoft.Copilot` を追加すれば可能です。ただしシステム機能への影響をご理解の上で行ってください。

## ライセンス

MIT License
