/**
 * Cloud Security Policy Engine
 * 
 * Validates PowerShell scripts against cloud security policies.
 * This engine checks compliance with organizational cloud security policies,
 * best practices, and security baselines using static analysis only.
 * 
 * This engine does NOT:
 * - Execute scripts
 * - Calculate risk scores
 * - Make allow/block decisions
 */

import type { CloudExecutionContext } from '../cloudExecutionContext/CloudExecutionContextEngine';
import { ExecutionEnvironmentType, PrivilegeLevel } from '../cloudExecutionContext/CloudExecutionContextEngine';

/**
 * Policy severity levels
 */
export enum PolicySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Policy categories for organization
 */
export type PolicyCategory = 
  | 'authentication'
  | 'authorization'
  | 'data_protection'
  | 'network_security'
  | 'resource_access'
  | 'logging'
  | 'compliance'
  | 'code_quality';

/**
 * Detection result from policy evaluation
 */
export interface PolicyDetectionResult {
  /** Whether the policy was violated */
  violated: boolean;
  /** Evidence found that triggered the violation */
  evidence: string[];
  /** Line numbers where violations were detected (if available) */
  lineNumbers?: number[];
  /** Additional context about the violation */
  context?: string;
}

/**
 * Policy detection function signature
 * 
 * @param scriptContent - The PowerShell script content to analyze
 * @param staticAnalysisFeatures - Features extracted by static analysis
 * @param cloudContext - Cloud execution context information
 * @returns Detection result indicating if policy was violated
 */
export type PolicyDetector = (
  scriptContent: string,
  staticAnalysisFeatures: any,
  cloudContext: CloudExecutionContext
) => PolicyDetectionResult;

/**
 * Cloud security policy definition
 */
export interface SecurityPolicy {
  /** Unique policy identifier */
  id: string;
  /** Human-readable policy name */
  name: string;
  /** Detailed policy description */
  description: string;
  /** Policy severity level */
  severity: PolicySeverity;
  /** Policy category */
  category: PolicyCategory;
  /** Detection logic function */
  detector: PolicyDetector;
  /** Explanation message when policy is violated */
  explanation: string;
  /** Whether this policy is enabled */
  enabled?: boolean;
}

/**
 * Policy validation result for a single policy
 */
export interface PolicyValidationResult {
  /** The policy that was evaluated */
  policy: SecurityPolicy;
  /** Whether the policy passed (no violations) */
  passed: boolean;
  /** Violations found (if any) */
  violations: PolicyViolation[];
  /** Evidence collected during evaluation */
  evidence: string[];
}

/**
 * Individual policy violation
 */
export interface PolicyViolation {
  /** Severity of the violation */
  severity: PolicySeverity;
  /** Description of the violation */
  description: string;
  /** Line number where violation was detected (if available) */
  lineNumber?: number;
  /** Evidence that triggered the violation */
  evidence: string;
  /** Policy ID that was violated */
  policyId: string;
  /** Explanation message */
  explanation: string;
}

/**
 * Complete policy validation report
 */
export interface PolicyValidationReport {
  /** Overall compliance score (0-100) */
  overallCompliance: number;
  /** Results for each policy evaluated */
  validationResults: PolicyValidationResult[];
  /** All violations found, grouped by severity */
  violations: PolicyViolation[];
  /** Critical violations (for quick access) */
  criticalViolations: PolicyViolation[];
  /** High severity violations */
  highViolations: PolicyViolation[];
  /** Medium severity violations */
  mediumViolations: PolicyViolation[];
  /** Low severity violations */
  lowViolations: PolicyViolation[];
  /** Recommendations based on violations */
  recommendations: string[];
}

/**
 * Cloud Security Policy Engine
 * 
 * Evaluates PowerShell scripts against cloud security policies using static analysis.
 */
export class CloudSecurityPolicyEngine {
  private policies: SecurityPolicy[] = [];

  /**
   * Constructor - initializes with default policies
   */
  constructor() {
    this.loadPolicies(this.getDefaultPolicies());
  }

  /**
   * Load security policies
   * 
   * @param policies - Array of security policies to validate against
   */
  loadPolicies(policies: SecurityPolicy[]): void {
    this.policies = policies.filter(p => p.enabled !== false);
  }

  /**
   * Get all available policies (including disabled ones)
   * 
   * @returns Array of all security policies
   */
  getAllPolicies(): SecurityPolicy[] {
    return this.getDefaultPolicies();
  }

  /**
   * Get currently loaded/enabled policies
   * 
   * @returns Array of currently enabled policies
   */
  getEnabledPolicies(): SecurityPolicy[] {
    return [...this.policies];
  }

  /**
   * Set enabled policies by policy IDs
   * 
   * @param enabledPolicyIds - Array of policy IDs to enable
   */
  setEnabledPolicies(enabledPolicyIds: string[]): void {
    const allPolicies = this.getDefaultPolicies();
    const enabledPolicies = allPolicies.filter(p => enabledPolicyIds.includes(p.id));
    this.loadPolicies(enabledPolicies);
  }

  /**
   * Validate script against loaded security policies
   * 
   * @param scriptContent - The PowerShell script content
   * @param staticAnalysisFeatures - Features extracted by static analysis
   * @param cloudContext - Cloud execution context information
   * @returns Policy validation report
   */
  validate(
    scriptContent: string,
    staticAnalysisFeatures: any,
    cloudContext: CloudExecutionContext
  ): PolicyValidationReport {
    const validationResults: PolicyValidationResult[] = [];
    const allViolations: PolicyViolation[] = [];

    // Evaluate each policy
    for (const policy of this.policies) {
      const detectionResult = policy.detector(scriptContent, staticAnalysisFeatures, cloudContext);
      
      const violations: PolicyViolation[] = [];
      if (detectionResult.violated) {
        // Create violation for each piece of evidence
        detectionResult.evidence.forEach((evidence, index) => {
          violations.push({
            severity: policy.severity,
            description: `${policy.name}: ${detectionResult.context || evidence}`,
            lineNumber: detectionResult.lineNumbers?.[index],
            evidence,
            policyId: policy.id,
            explanation: policy.explanation
          });
        });
        
        allViolations.push(...violations);
      }

      validationResults.push({
        policy,
        passed: !detectionResult.violated,
        violations,
        evidence: detectionResult.evidence
      });
    }

    // Group violations by severity
    const criticalViolations = allViolations.filter(v => v.severity === PolicySeverity.CRITICAL);
    const highViolations = allViolations.filter(v => v.severity === PolicySeverity.HIGH);
    const mediumViolations = allViolations.filter(v => v.severity === PolicySeverity.MEDIUM);
    const lowViolations = allViolations.filter(v => v.severity === PolicySeverity.LOW);

    // Calculate overall compliance score
    const totalPolicies = validationResults.length;
    const passedPolicies = validationResults.filter(r => r.passed).length;
    const overallCompliance = totalPolicies > 0 
      ? Math.round((passedPolicies / totalPolicies) * 100)
      : 100;

    // Generate recommendations
    const recommendations = this.generateRecommendations(allViolations, cloudContext);

    return {
      overallCompliance,
      validationResults,
      violations: allViolations,
      criticalViolations,
      highViolations,
      mediumViolations,
      lowViolations,
      recommendations
    };
  }

  /**
   * Get default cloud security policies
   * 
   * @returns Array of default security policies
   */
  private getDefaultPolicies(): SecurityPolicy[] {
    return [
      // Encoded PowerShell commands in production contexts
      {
        id: 'POL-001',
        name: 'Encoded PowerShell in Production',
        description: 'Detects encoded PowerShell commands (Base64, obfuscated) in production execution contexts',
        severity: PolicySeverity.HIGH,
        category: 'code_quality',
        explanation: 'Encoded PowerShell commands in production environments can indicate obfuscation attempts or security risks. Consider using clear, auditable code.',
        detector: (content, features, context) => {
          const lowerContent = content.toLowerCase();
          const hasEncodedContent = features?.base64Count > 0 || 
                                   features?.encodingMethodCount > 2 ||
                                   lowerContent.includes('frombase64string') ||
                                   lowerContent.includes('tobase64string');
          
          // More critical in production contexts
          const isProductionContext = context.environmentType === ExecutionEnvironmentType.CI_CD_PIPELINE ||
                                     context.environmentType === ExecutionEnvironmentType.ADMIN_AUTOMATION;
          
          if (hasEncodedContent && isProductionContext) {
            const evidence: string[] = [];
            if (features?.base64Count > 0) {
              evidence.push(`${features.base64Count} Base64 encoded string(s) detected`);
            }
            if (features?.encodingMethodCount > 2) {
              evidence.push(`Multiple encoding methods detected: ${features.encodingMethodCount}`);
            }
            if (lowerContent.includes('frombase64string') || lowerContent.includes('tobase64string')) {
              evidence.push('Base64 encoding/decoding operations detected');
            }
            
            return {
              violated: true,
              evidence,
              context: `Encoded PowerShell detected in ${context.environmentType} context`
            };
          }
          
          return { violated: false, evidence: [] };
        }
      },

      // Privilege escalation or role assignment operations
      {
        id: 'POL-002',
        name: 'Privilege Escalation Operations',
        description: 'Detects privilege escalation or role assignment operations',
        severity: PolicySeverity.CRITICAL,
        category: 'authorization',
        explanation: 'Privilege escalation operations can grant excessive permissions. Ensure proper authorization and audit trails.',
        detector: (content, _features, context) => {
          const lowerContent = content.toLowerCase();
          const privilegeIndicators = [
            'new-azroleassignment',
            'new-azadapproleassignment',
            'set-azroleassignment',
            'grant-azroleassignment',
            'new-iamrole',
            'attach-role-policy',
            'iam:passrole',
            'runas administrator',
            'start-process -verb runas',
            'elevate',
            'privilege escalation',
            'sudo',
            'runas /user:administrator'
          ];
          
          const foundIndicators = privilegeIndicators.filter(indicator => 
            lowerContent.includes(indicator)
          );
          
          if (foundIndicators.length > 0) {
            // More critical if not using managed identity
            const isHighRisk = context.privilegeLevel !== PrivilegeLevel.MANAGED_IDENTITY;
            
            return {
              violated: true,
              evidence: foundIndicators,
              context: isHighRisk 
                ? 'Privilege escalation detected without managed identity context'
                : 'Privilege escalation operations detected'
            };
          }
          
          return { violated: false, evidence: [] };
        }
      },

      // Token or credential access patterns
      {
        id: 'POL-003',
        name: 'Hardcoded Credentials or Token Access',
        description: 'Detects hardcoded credentials, token access patterns, or insecure credential handling',
        severity: PolicySeverity.CRITICAL,
        category: 'authentication',
        explanation: 'Hardcoded credentials or insecure token handling can lead to credential exposure. Use secure credential management (Key Vault, Secrets Manager, etc.).',
        detector: (content, features, context) => {
          const lowerContent = content.toLowerCase();
          const credentialPatterns = [
            'password\s*=\s*["\']',
            'pwd\s*=\s*["\']',
            'pass\s*=\s*["\']',
            'secret\s*=\s*["\']',
            'token\s*=\s*["\']',
            'apikey\s*=\s*["\']',
            'api_key\s*=\s*["\']',
            'get-credential',
            'convertto-securestring.*-asplaintext',
            'plaintext',
            'decrypt.*password'
          ];
          
          const foundPatterns: string[] = [];
          credentialPatterns.forEach(pattern => {
            const regex = new RegExp(pattern, 'i');
            if (regex.test(content)) {
              foundPatterns.push(`Pattern detected: ${pattern}`);
            }
          });
          
          // Check for long strings that might be tokens/keys
          if (features?.maxStringLength > 100 && lowerContent.includes('token')) {
            foundPatterns.push('Potential token in long string detected');
          }
          
          if (foundPatterns.length > 0) {
            return {
              violated: true,
              evidence: foundPatterns,
              context: 'Potential credential or token exposure detected'
            };
          }
          
          return { violated: false, evidence: [] };
        }
      },

      // Network download or remote execution commands
      {
        id: 'POL-004',
        name: 'Unrestricted Network Downloads',
        description: 'Detects network download operations without proper validation',
        severity: PolicySeverity.HIGH,
        category: 'network_security',
        explanation: 'Unrestricted network downloads can introduce security risks. Validate sources and use allowlists where possible.',
        detector: (content, features, context) => {
          const lowerContent = content.toLowerCase();
          const downloadIndicators = [
            'invoke-webrequest',
            'invoke-restmethod',
            'downloadstring',
            'downloadfile',
            'webclient',
            'net.webclient',
            'start-bitstransfer'
          ];
          
          const foundIndicators = downloadIndicators.filter(indicator => 
            lowerContent.includes(indicator)
          );
          
          if (foundIndicators.length > 0 && context.networkExposure === 'internet_facing') {
            // Check if URLs are present
            const hasUrls = features?.urlCount > 0;
            const hasIps = features?.ipCount > 0;
            
            const evidence: string[] = [];
            foundIndicators.forEach(ind => evidence.push(`Download command: ${ind}`));
            if (hasUrls) {
              evidence.push(`${features.urlCount} URL(s) detected`);
            }
            if (hasIps) {
              evidence.push(`${features.ipCount} IP address(es) detected`);
            }
            
            return {
              violated: true,
              evidence,
              context: 'Network download operations detected with internet exposure'
            };
          }
          
          return { violated: false, evidence: [] };
        }
      },

      // Remote execution commands
      {
        id: 'POL-005',
        name: 'Remote Code Execution',
        description: 'Detects remote code execution patterns',
        severity: PolicySeverity.CRITICAL,
        category: 'network_security',
        explanation: 'Remote code execution can introduce significant security risks. Ensure proper authentication and authorization.',
        detector: (content, _features, context) => {
          const lowerContent = content.toLowerCase();
          const remoteExecutionIndicators = [
            'invoke-command -computername',
            'invoke-command -session',
            'new-pssession',
            'enter-pssession',
            'invoke-expression.*http',
            'iex.*downloadstring',
            'start-process.*http',
            'wmic.*process.*call.*create',
            'psexec',
            'winrm',
            'invoke-webrequest.*invoke-expression'
          ];
          
          const foundIndicators = remoteExecutionIndicators.filter(indicator => {
            const regex = new RegExp(indicator.replace(/\./g, '\\.'), 'i');
            return regex.test(content);
          });
          
          if (foundIndicators.length > 0) {
            return {
              violated: true,
              evidence: foundIndicators,
              context: 'Remote code execution patterns detected'
            };
          }
          
          return { violated: false, evidence: [] };
        }
      },

      // Execution policy bypass
      {
        id: 'POL-006',
        name: 'Execution Policy Bypass',
        description: 'Detects PowerShell execution policy bypass attempts',
        severity: PolicySeverity.MEDIUM,
        category: 'compliance',
        explanation: 'Execution policy bypasses can circumvent security controls. Ensure scripts comply with organizational policies.',
        detector: (content, features, _context) => {
          const lowerContent = content.toLowerCase();
          const bypassIndicators = [
            'bypass',
            'executionpolicy.*bypass',
            '-executionpolicy bypass',
            'set-executionpolicy.*bypass',
            'unrestricted',
            '-executionpolicy unrestricted'
          ];
          
          const foundIndicators = bypassIndicators.filter(indicator => {
            const regex = new RegExp(indicator.replace(/\./g, '\\.'), 'i');
            return regex.test(content);
          });
          
          if (foundIndicators.length > 0 || features?.suspiciousKeywords?.some((k: string) => 
            k.toLowerCase().includes('bypass') || k.toLowerCase().includes('executionpolicy')
          )) {
            return {
              violated: true,
              evidence: foundIndicators.length > 0 ? foundIndicators : ['Execution policy bypass keywords detected'],
              context: 'Execution policy bypass detected'
            };
          }
          
          return { violated: false, evidence: [] };
        }
      },

      // Insecure credential storage
      {
        id: 'POL-007',
        name: 'Insecure Credential Storage',
        description: 'Detects insecure credential storage patterns',
        severity: PolicySeverity.HIGH,
        category: 'data_protection',
        explanation: 'Credentials should be stored securely using cloud-native services (Key Vault, Secrets Manager). Avoid plaintext storage.',
        detector: (content, _features, context) => {
          const lowerContent = content.toLowerCase();
          const insecureStoragePatterns = [
            'out-file.*password',
            'set-content.*password',
            'export-clixml.*credential',
            'convertfrom-json.*password',
            '\.txt.*password',
            '\.xml.*credential',
            '\.json.*token'
          ];
          
          const foundPatterns: string[] = [];
          insecureStoragePatterns.forEach(pattern => {
            const regex = new RegExp(pattern, 'i');
            if (regex.test(content)) {
              foundPatterns.push(`Insecure storage pattern: ${pattern}`);
            }
          });
          
          // Check if script doesn't use secure credential services
          const usesSecureStorage = lowerContent.includes('keyvault') ||
                                   lowerContent.includes('secretsmanager') ||
                                   lowerContent.includes('azure key vault') ||
                                   lowerContent.includes('aws secrets manager');
          
          if (foundPatterns.length > 0 && !usesSecureStorage) {
            return {
              violated: true,
              evidence: foundPatterns,
              context: 'Insecure credential storage detected without secure credential service usage'
            };
          }
          
          return { violated: false, evidence: [] };
        }
      },

      // Excessive permissions in role assignments
      {
        id: 'POL-008',
        name: 'Excessive Role Permissions',
        description: 'Detects role assignments with potentially excessive permissions',
        severity: PolicySeverity.MEDIUM,
        category: 'authorization',
        explanation: 'Role assignments should follow principle of least privilege. Review permissions granted.',
        detector: (content, _features, context) => {
          const lowerContent = content.toLowerCase();
          const excessivePermissionIndicators = [
            'owner',
            'contributor',
            '*',
            'full',
            'all',
            'administrator',
            'admin'
          ];
          
          const roleAssignmentCommands = [
            'new-azroleassignment',
            'set-azroleassignment',
            'grant-azroleassignment',
            'new-iamrole',
            'attach-role-policy'
          ];
          
          const hasRoleAssignment = roleAssignmentCommands.some(cmd => 
            lowerContent.includes(cmd)
          );
          
          if (hasRoleAssignment) {
            const foundExcessive = excessivePermissionIndicators.filter(indicator => 
              lowerContent.includes(indicator)
            );
            
            if (foundExcessive.length > 0) {
              return {
                violated: true,
                evidence: foundExcessive.map(ind => `Excessive permission: ${ind}`),
                context: 'Role assignment with potentially excessive permissions detected'
              };
            }
          }
          
          return { violated: false, evidence: [] };
        }
      }
    ];
  }

  /**
   * Generate recommendations based on violations
   */
  private generateRecommendations(
    violations: PolicyViolation[],
    context: CloudExecutionContext
  ): string[] {
    const recommendations: string[] = [];
    
    if (violations.length === 0) {
      return ['No policy violations detected. Script appears compliant with cloud security policies.'];
    }
    
    // Critical violations
    const criticalCount = violations.filter(v => v.severity === PolicySeverity.CRITICAL).length;
    if (criticalCount > 0) {
      recommendations.push(`🚨 ${criticalCount} CRITICAL violation(s) detected. Immediate review required.`);
    }
    
    // High violations
    const highCount = violations.filter(v => v.severity === PolicySeverity.HIGH).length;
    if (highCount > 0) {
      recommendations.push(`⚠️ ${highCount} HIGH severity violation(s) detected. Review recommended.`);
    }
    
    // Specific recommendations based on violation types
    const violationIds = new Set(violations.map(v => v.policyId));
    
    if (violationIds.has('POL-001')) {
      recommendations.push('Consider removing encoded PowerShell commands. Use clear, auditable code in production.');
    }
    
    if (violationIds.has('POL-002')) {
      recommendations.push('Review privilege escalation operations. Consider using managed identities instead.');
    }
    
    if (violationIds.has('POL-003')) {
      recommendations.push('Remove hardcoded credentials. Use Azure Key Vault, AWS Secrets Manager, or GCP Secret Manager.');
    }
    
    if (violationIds.has('POL-004') || violationIds.has('POL-005')) {
      recommendations.push('Validate network download sources. Use allowlists and verify SSL certificates.');
    }
    
    if (violationIds.has('POL-006')) {
      recommendations.push('Remove execution policy bypasses. Ensure scripts comply with organizational policies.');
    }
    
    if (violationIds.has('POL-007')) {
      recommendations.push('Use secure credential storage services. Avoid storing credentials in files or variables.');
    }
    
    if (violationIds.has('POL-008')) {
      recommendations.push('Apply principle of least privilege. Grant only necessary permissions for role assignments.');
    }
    
    // Context-specific recommendations
    if (context.privilegeLevel === PrivilegeLevel.ADMIN && violations.length > 0) {
      recommendations.push('Script runs with admin privileges. Ensure all operations are necessary and properly authorized.');
    }
    
    if (context.networkExposure === 'internet_facing' && violations.some(v => 
      v.policyId === 'POL-004' || v.policyId === 'POL-005'
    )) {
      recommendations.push('Script has internet exposure. Implement additional network security controls.');
    }
    
    return recommendations;
  }

  /**
   * Add a custom policy
   * 
   * @param policy - Security policy to add
   */
  addPolicy(policy: SecurityPolicy): void {
    this.policies.push(policy);
  }

  /**
   * Remove a policy by ID
   * 
   * @param policyId - ID of policy to remove
   */
  removePolicy(policyId: string): void {
    this.policies = this.policies.filter(p => p.id !== policyId);
  }

  /**
   * Get all loaded policies
   * 
   * @returns Array of loaded policies
   */
  getPolicies(): SecurityPolicy[] {
    return [...this.policies];
  }

  /**
   * Enable or disable a policy
   * 
   * @param policyId - ID of policy to enable/disable
   * @param enabled - Whether to enable the policy
   */
  setPolicyEnabled(policyId: string, enabled: boolean): void {
    const policy = this.policies.find(p => p.id === policyId);
    if (policy) {
      policy.enabled = enabled;
    }
  }
}
