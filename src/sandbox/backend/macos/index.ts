import type {
  HelperProcessPreparation,
  PrepareHelperProcess,
} from "#sandbox/lifecycle";
import { buildSeatbeltProfile, MACOS_SANDBOX_EXEC_PATH, probeMacOSSeatbelt } from "#sandbox/backend/macos/seatbelt";

export * from "#sandbox/backend/macos/seatbelt";

export const prepareMacOSHelperProcess: PrepareHelperProcess = ({
  installation,
  spec,
  plan,
}): HelperProcessPreparation => {
  const probe = probeMacOSSeatbelt();
  if (probe.status !== "candidate-present") {
    return {
      ok: false,
      code: "sandbox-unavailable",
      reason: probe.reason,
    };
  }
  const policy = buildSeatbeltProfile({
    installation,
    helperHome: spec.environment.HOME,
    ...(plan === undefined ? {} : { plan }),
  });
  if (!policy.ok) return policy;
  return {
    ok: true,
    spec: {
      executable: MACOS_SANDBOX_EXEC_PATH,
      args: ["-p", policy.profile, spec.executable, ...spec.args],
      cwd: spec.cwd,
      environment: spec.environment,
    },
  };
};
