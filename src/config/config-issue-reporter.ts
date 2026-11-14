/**
 * Configuration issue reporter (specs/config-loading.md §11).
 *
 * The formal owner and the unified loader produce displayable `ConfigMessage`
 * values; the host hands those to this reporter at session start and at turn
 * preparation. The reporter keeps one latch: the set of messages already
 * reported. Each `report()` diffs the current set against the latch, emits the
 * genuinely new messages as one notification, and then replaces the latch with
 * the current set — so an issue that disappears and comes back is reported
 * again, while a persistent issue is announced only once.
 *
 * Reporting is advisory: a throwing reader or notification callback must never
 * change the effective configuration, so both are isolated.
 */
import {
  configMessageKey,
  formatConfigMessage,
  type ConfigMessage,
} from "#config/config-loader";

export interface ConfigIssueReporterOptions {
  /** Reads the configuration messages that are currently in effect. */
  readonly readIssues: () => readonly ConfigMessage[];
  /** Emits the combined notification for newly observed messages. */
  readonly notify: (message: string) => void;
}

export interface ConfigIssueReporter {
  /** Reads the current issues, notifies the new ones and returns them. */
  report(): readonly ConfigMessage[];
}

/**
 * Create a configuration issue reporter.
 *
 * The latch lives in this closure, so one reporter instance owns one reported
 * set for the lifetime of the session.
 */
export function createConfigIssueReporter(
  options: ConfigIssueReporterOptions,
): ConfigIssueReporter {
  let reportedKeys: ReadonlySet<string> = new Set<string>();

  return {
    report(): readonly ConfigMessage[] {
      let current: readonly ConfigMessage[];
      try {
        current = options.readIssues();
      } catch {
        // A failing reader is not a configuration problem to report.
        return [];
      }

      const currentKeys = new Set<string>();
      const added: ConfigMessage[] = [];
      for (const message of current) {
        const key = configMessageKey(message);
        if (currentKeys.has(key)) continue;
        currentKeys.add(key);
        if (!reportedKeys.has(key)) added.push(message);
      }
      // Replace, never union: a resolved issue must be forgotten so that a
      // later reappearance is announced again.
      reportedKeys = currentKeys;

      if (added.length > 0) {
        try {
          options.notify(added.map(formatConfigMessage).join("\n"));
        } catch {
          // A broken notification channel must not affect the reported result.
        }
      }
      return added;
    },
  };
}
