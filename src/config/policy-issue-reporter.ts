/**
 * Policy issue reporter (specs/config-loading.md §11).
 *
 * Policy composition problems — a non-global configuration scope that failed
 * to load and must be clamped fail-closed, or a legacy MCP key that needs a
 * migration — use the same display model and the same latch as configuration
 * issues, but they are reported separately so schema details and composition
 * details are each announced once.
 *
 * The latch is shared across agents: the reporter is created once per session,
 * and every `report(agentName)` compares the current agent's issues against the
 * single set already announced. Policy loading happens at session start and at
 * turn preparation with the agent that is current at that moment.
 */
import {
  configMessageKey,
  formatConfigMessage,
  type ConfigMessage,
} from "#config/config-loader";

export interface PolicyIssueReporterOptions {
  /** Reads the policy composition messages for the given agent. */
  readonly readIssues: (agentName: string) => readonly ConfigMessage[];
  /** Emits the combined notification for newly observed messages. */
  readonly notify: (message: string) => void;
}

export interface PolicyIssueReporter {
  /** Reads the current agent's issues, notifies the new ones and returns them. */
  report(agentName: string): readonly ConfigMessage[];
}

/** Create a policy issue reporter whose latch is shared across agents. */
export function createPolicyIssueReporter(
  options: PolicyIssueReporterOptions,
): PolicyIssueReporter {
  let reportedKeys: ReadonlySet<string> = new Set<string>();

  return {
    report(agentName: string): readonly ConfigMessage[] {
      let current: readonly ConfigMessage[];
      try {
        current = options.readIssues(agentName);
      } catch {
        // A failing policy reader is not a policy problem to report.
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
