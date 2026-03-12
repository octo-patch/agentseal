/**
 * Desktop notifications for AgentSeal Shield.
 *
 * Uses OS built-in notification mechanisms — no additional dependencies.
 * macOS: osascript, Linux: notify-send, Fallback: terminal bell + stderr.
 *
 * Port of Python agentseal/notify.py.
 */

import { execFileSync } from "node:child_process";
import { platform } from "node:os";

const SEVERITY_ICONS: Record<string, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
};

export class Notifier {
  private _enabled: boolean;
  private _minInterval: number;
  private _lastNotifyTime: number = -Infinity;
  private _platform: string;

  constructor(enabled = true, minInterval = 30.0) {
    this._enabled = enabled;
    this._minInterval = minInterval;
    this._platform = platform();
  }

  get enabled(): boolean {
    return this._enabled;
  }

  /** Send a desktop notification. Returns true if sent. Respects throttle interval. */
  notify(title: string, message: string, urgent = false): boolean {
    if (!this._enabled) return false;

    const now = performance.now() / 1000;
    if (now - this._lastNotifyTime < this._minInterval) return false;

    const sent = this._dispatch(title, message, urgent);
    if (sent) this._lastNotifyTime = now;
    return sent;
  }

  /** Send a threat notification with standard formatting. */
  notifyThreat(
    itemName: string,
    itemType: string,
    severity: string,
    detail: string,
  ): boolean {
    const level = SEVERITY_ICONS[severity] ?? severity.toUpperCase();
    const title = `AgentSeal Shield - ${level}`;
    const message = `${itemType}: ${itemName}\n${detail}`;
    return this.notify(title, message, severity === "critical" || severity === "high");
  }

  private _dispatch(title: string, message: string, urgent: boolean): boolean {
    if (this._platform === "darwin") return this._notifyMacOS(title, message, urgent);
    if (this._platform === "linux") return this._notifyLinux(title, message, urgent);
    return this._notifyFallback(title, message);
  }

  private _notifyMacOS(title: string, message: string, urgent: boolean): boolean {
    const safeTitle = title.replace(/"/g, '\\"');
    const safeMessage = message.replace(/"/g, '\\"').replace(/\n/g, " - ");
    const sound = urgent ? ' sound name "Basso"' : "";
    const script = `display notification "${safeMessage}" with title "${safeTitle}"${sound}`;
    try {
      execFileSync("osascript", ["-e", script], { timeout: 5000, stdio: "pipe" });
      return true;
    } catch {
      return this._notifyFallback(title, message);
    }
  }

  private _notifyLinux(title: string, message: string, urgent: boolean): boolean {
    const urgency = urgent ? "critical" : "normal";
    try {
      execFileSync(
        "notify-send",
        [title, message, `--urgency=${urgency}`, "--icon=dialog-warning"],
        { timeout: 5000, stdio: "pipe" },
      );
      return true;
    } catch {
      return this._notifyFallback(title, message);
    }
  }

  private _notifyFallback(title: string, message: string): boolean {
    process.stderr.write(`\x07\x1b[93m[${title}]\x1b[0m ${message}\n`);
    return true;
  }
}
