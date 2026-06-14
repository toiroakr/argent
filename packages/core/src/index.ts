export { evaluatePackage, availableProviders } from "./evaluate.js";
export type { EvaluateOptions } from "./evaluate.js";
export { auditDependencies, auditEntries } from "./audit.js";
export type { AuditReport, AuditOptions, AuditEntry, DepAudit } from "./audit.js";
export { aggregate, worse, levelFromScore, levelFromSeverity } from "./risk.js";
export type {
  RiskLevel,
  RiskReport,
  ProviderResult,
  ProviderFinding,
  PackageRef,
  EvalConfig,
  EvalContext,
  Provider,
} from "./types.js";
