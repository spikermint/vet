export type Severity = "critical" | "high" | "medium" | "low";

export type ExposureRisk = "inHistory" | "notInHistory" | "unknown";

export type VerificationStatus = "live" | "inactive" | "inconclusive";

export interface HoverData {
	patternName: string;
	severity: Severity;
	description: string;
	verification?: VerificationInfo;
	remediation: RemediationInfo;
}

export interface VerificationInfo {
	status: VerificationStatus;
	provider?: string;
	details?: string;
	reason?: string;
	verifiedAt: string;
}

export interface RemediationInfo {
	exposure: ExposureRisk;
	advice: string;
}

export interface VetHoverResponse {
	data: HoverData;
	range?: {
		start: { line: number; character: number };
		end: { line: number; character: number };
	};
}

export interface DiagnosticData {
	fingerprint: string;
	findingId: string;
	verifiable: boolean;
	verification?: DiagnosticVerification;
}

export interface DiagnosticVerification {
	status: VerificationStatus;
	provider?: string;
	details?: string;
	verifiedAt: string;
}
