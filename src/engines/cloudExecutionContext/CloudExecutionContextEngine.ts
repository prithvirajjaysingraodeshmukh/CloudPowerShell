/**
 * Cloud Execution Context Engine
 * 
 * Evaluates the cloud execution context for PowerShell scripts.
 * This engine determines the execution environment, privilege level, and network exposure
 * that a script would have when executed in a cloud environment.
 * 
 * This engine only exposes structured context data - it does NOT:
 * - Execute scripts
 * - Perform security decisions
 * - Perform policy validation
 */

/**
 * Execution environment types where PowerShell scripts may run
 */
export enum ExecutionEnvironmentType {
  /** Script runs on a cloud virtual machine (VM) */
  CLOUD_VM = 'cloud_vm',
  /** Script runs as part of a CI/CD pipeline (Azure DevOps, GitHub Actions, etc.) */
  CI_CD_PIPELINE = 'ci_cd_pipeline',
  /** Script runs as administrative automation (scheduled tasks, runbooks, etc.) */
  ADMIN_AUTOMATION = 'admin_automation'
}

/**
 * Privilege levels for script execution
 */
export enum PrivilegeLevel {
  /** Standard user privileges */
  USER = 'user',
  /** Administrative privileges */
  ADMIN = 'admin',
  /** Managed identity (Azure) or IAM role (AWS/GCP) */
  MANAGED_IDENTITY = 'managed_identity'
}

/**
 * Network exposure levels
 */
export enum NetworkExposure {
  /** Script only accesses internal/private network resources */
  INTERNAL = 'internal',
  /** Script may access internet-facing resources */
  INTERNET_FACING = 'internet_facing'
}

/**
 * Cloud platform identifiers
 */
export enum CloudPlatform {
  AWS = 'aws',
  AZURE = 'azure',
  GCP = 'gcp',
  MULTI = 'multi',
  UNKNOWN = 'unknown'
}

/**
 * Cloud execution context data model
 * 
 * Represents the complete execution context for a PowerShell script
 * in a cloud environment.
 */
export interface CloudExecutionContext {
  /** Type of execution environment */
  environmentType: ExecutionEnvironmentType;
  
  /** Privilege level for script execution */
  privilegeLevel: PrivilegeLevel;
  
  /** Network exposure level */
  networkExposure: NetworkExposure;
  
  /** Cloud platform(s) the script targets */
  platform: CloudPlatform;
  
  /** Cloud service identifiers that the script may interact with */
  cloudServices: string[];
  
  /** Cloud APIs that might be called */
  cloudApis: CloudApi[];
  
  /** Cloud resources that could be accessed */
  cloudResources: CloudResource[];
  
  /** Additional context assumptions and metadata */
  metadata: ContextMetadata;
}

/**
 * Cloud API call information
 */
export interface CloudApi {
  /** Cloud service name (e.g., "Azure Storage", "AWS S3") */
  service: string;
  /** API name or endpoint */
  apiName: string;
  /** Operation type (e.g., "Get", "Put", "Delete") */
  operation: string;
  /** Indicators found in script that suggest this API usage */
  indicators: string[];
}

/**
 * Cloud resource reference
 */
export interface CloudResource {
  /** Resource type (e.g., "storage_account", "vm", "database") */
  type: string;
  /** Resource identifier if detected */
  identifier?: string;
  /** Permissions or access patterns detected */
  permissions?: string[];
}

/**
 * Additional context metadata
 */
export interface ContextMetadata {
  /** Confidence level in the context assessment (0-1) */
  confidence: number;
  /** Assumptions made during analysis */
  assumptions: string[];
  /** Detected patterns that influenced context determination */
  detectedPatterns: string[];
}

/**
 * Default cloud execution context configuration
 * 
 * Represents a safe default context when no specific indicators are found.
 */
export const DEFAULT_CONTEXT: CloudExecutionContext = {
  environmentType: ExecutionEnvironmentType.CLOUD_VM,
  privilegeLevel: PrivilegeLevel.USER,
  networkExposure: NetworkExposure.INTERNAL,
  platform: CloudPlatform.UNKNOWN,
  cloudServices: [],
  cloudApis: [],
  cloudResources: [],
  metadata: {
    confidence: 0.5,
    assumptions: ['Default context - no specific indicators detected'],
    detectedPatterns: []
  }
};

/**
 * Cloud Execution Context Engine
 * 
 * Analyzes PowerShell scripts to determine their cloud execution context
 * without making security decisions or executing code.
 */
export class CloudExecutionContextEngine {
  /**
   * Analyze script to determine cloud execution context
   * 
   * @param scriptContent - The PowerShell script content
   * @param staticAnalysisFeatures - Features extracted by static analysis
   * @param contextOverrides - Optional partial context overrides (privilege level, environment type)
   * @returns Cloud execution context information
   */
  analyze(
    scriptContent: string, 
    staticAnalysisFeatures: any,
    contextOverrides?: Partial<Pick<CloudExecutionContext, 'privilegeLevel' | 'environmentType'>>
  ): CloudExecutionContext {
    const lowerContent = scriptContent.toLowerCase();
    
    // Determine execution environment type (use override if provided)
    const environmentType = contextOverrides?.environmentType 
      ?? this.detectEnvironmentType(lowerContent, staticAnalysisFeatures);
    
    // Determine privilege level (use override if provided)
    const privilegeLevel = contextOverrides?.privilegeLevel 
      ?? this.detectPrivilegeLevel(lowerContent, staticAnalysisFeatures);
    
    // Determine network exposure
    const networkExposure = this.detectNetworkExposure(lowerContent, staticAnalysisFeatures);
    
    // Determine cloud platform
    const platform = this.detectCloudPlatform(lowerContent, staticAnalysisFeatures);
    
    // Detect cloud services
    const cloudServices = this.detectCloudServices(lowerContent);
    
    // Detect cloud APIs
    const cloudApis = this.detectCloudApis(lowerContent);
    
    // Detect cloud resources
    const cloudResources = this.detectCloudResources(lowerContent);
    
    // Build metadata
    const metadata = this.buildMetadata(
      environmentType,
      privilegeLevel,
      networkExposure,
      platform,
      lowerContent
    );
    
    // Build and validate context
    const context: CloudExecutionContext = {
      environmentType,
      privilegeLevel,
      networkExposure,
      platform,
      cloudServices,
      cloudApis,
      cloudResources,
      metadata
    };
    
    // Validate context for invalid combinations
    this.validateContext(context);
    
    return context;
  }

  /**
   * Detect execution environment type from script content
   */
  private detectEnvironmentType(content: string, _features: any): ExecutionEnvironmentType {
    // CI/CD Pipeline indicators
    const ciCdIndicators = [
      'azure-pipelines',
      'github actions',
      'gitlab-ci',
      'jenkins',
      'azure devops',
      'pipeline',
      'build agent',
      'release pipeline'
    ];
    
    if (ciCdIndicators.some(indicator => content.includes(indicator))) {
      return ExecutionEnvironmentType.CI_CD_PIPELINE;
    }
    
    // Admin Automation indicators
    const adminAutomationIndicators = [
      'runbook',
      'automation account',
      'scheduled task',
      'task scheduler',
      'azure automation',
      'aws systems manager',
      'gcp cloud scheduler',
      'workflow',
      'orchestration'
    ];
    
    if (adminAutomationIndicators.some(indicator => content.includes(indicator))) {
      return ExecutionEnvironmentType.ADMIN_AUTOMATION;
    }
    
    // Default to Cloud VM
    return ExecutionEnvironmentType.CLOUD_VM;
  }

  /**
   * Detect privilege level from script content
   */
  private detectPrivilegeLevel(content: string, _features: any): PrivilegeLevel {
    // Managed Identity indicators (Azure)
    const managedIdentityIndicators = [
      'managedidentity',
      'managed identity',
      'system.managedidentityservice',
      'get-azcontext',
      'connect-azaccount -identity',
      'invoke-restmethod -identity'
    ];
    
    if (managedIdentityIndicators.some(indicator => content.includes(indicator))) {
      return PrivilegeLevel.MANAGED_IDENTITY;
    }
    
    // Admin indicators
    const adminIndicators = [
      'runas administrator',
      'elevated',
      'administrator',
      'localadmin',
      'domain admin',
      'get-credential',
      'invoke-command -credential',
      'start-process -verb runas'
    ];
    
    if (adminIndicators.some(indicator => content.includes(indicator))) {
      return PrivilegeLevel.ADMIN;
    }
    
    // Default to user privileges
    return PrivilegeLevel.USER;
  }

  /**
   * Detect network exposure from script content
   */
  private detectNetworkExposure(content: string, features: any): NetworkExposure {
    // Use features to check for network activity
    // Check for internet-facing indicators
    const internetIndicators = [
      'invoke-webrequest',
      'invoke-restmethod',
      'downloadstring',
      'downloadfile',
      'http://',
      'https://',
      'api.github.com',
      'api.azure.com',
      'amazonaws.com',
      'googleapis.com'
    ];
    
    // Check if script has network indicators from static analysis
    const hasNetworkActivity = features?.urlCount > 0 || features?.ipCount > 0;
    
    if (hasNetworkActivity || internetIndicators.some(indicator => content.includes(indicator))) {
      return NetworkExposure.INTERNET_FACING;
    }
    
    // Default to internal
    return NetworkExposure.INTERNAL;
  }

  /**
   * Detect cloud platform from script content
   */
  private detectCloudPlatform(content: string, _features: any): CloudPlatform {
    const platformIndicators = {
      [CloudPlatform.AZURE]: [
        'azure',
        'az.',
        'get-az',
        'set-az',
        'new-az',
        'remove-az',
        'connect-azaccount',
        'azure.management',
        'azure.storage',
        'management.azure.com'
      ],
      [CloudPlatform.AWS]: [
        'aws',
        'get-aws',
        'set-aws',
        'new-aws',
        'remove-aws',
        'aws s3',
        'aws ec2',
        'amazonaws.com',
        'aws.tools'
      ],
      [CloudPlatform.GCP]: [
        'gcp',
        'gcloud',
        'google cloud',
        'googleapis.com',
        'gcp.tools'
      ]
    };
    
    const detectedPlatforms: CloudPlatform[] = [];
    
    // Check for Azure indicators
    if (platformIndicators[CloudPlatform.AZURE].some(indicator => content.includes(indicator))) {
      detectedPlatforms.push(CloudPlatform.AZURE);
    }
    
    // Check for AWS indicators
    if (platformIndicators[CloudPlatform.AWS].some(indicator => content.includes(indicator))) {
      detectedPlatforms.push(CloudPlatform.AWS);
    }
    
    // Check for GCP indicators
    if (platformIndicators[CloudPlatform.GCP].some(indicator => content.includes(indicator))) {
      detectedPlatforms.push(CloudPlatform.GCP);
    }
    
    if (detectedPlatforms.length > 1) {
      return CloudPlatform.MULTI;
    } else if (detectedPlatforms.length === 1) {
      return detectedPlatforms[0];
    }
    
    return CloudPlatform.UNKNOWN;
  }

  /**
   * Detect cloud services from script content
   */
  private detectCloudServices(content: string): string[] {
    const services: string[] = [];
    
    // Azure services
    const azureServices = {
      'Azure Storage': ['azure.storage', 'storage account', 'blob', 'table storage'],
      'Azure Key Vault': ['keyvault', 'key vault', 'get-azkeyvault'],
      'Azure Compute': ['vm', 'virtual machine', 'get-azvm'],
      'Azure Functions': ['function app', 'azure function'],
      'Azure SQL': ['sql database', 'azuresql', 'get-azsqldatabase']
    };
    
    // AWS services
    const awsServices = {
      'AWS S3': ['s3', 'amazon s3', 'get-s3object'],
      'AWS EC2': ['ec2', 'get-ec2instance'],
      'AWS Lambda': ['lambda', 'aws lambda'],
      'AWS Secrets Manager': ['secretsmanager', 'get-secretvalue']
    };
    
    // GCP services
    const gcpServices = {
      'GCP Storage': ['gcs', 'google cloud storage'],
      'GCP Compute': ['gce', 'compute engine'],
      'GCP Cloud Functions': ['cloud function', 'gcp function']
    };
    
    // Check for Azure services
    Object.entries(azureServices).forEach(([service, indicators]) => {
      if (indicators.some(indicator => content.includes(indicator))) {
        services.push(service);
      }
    });
    
    // Check for AWS services
    Object.entries(awsServices).forEach(([service, indicators]) => {
      if (indicators.some(indicator => content.includes(indicator))) {
        services.push(service);
      }
    });
    
    // Check for GCP services
    Object.entries(gcpServices).forEach(([service, indicators]) => {
      if (indicators.some(indicator => content.includes(indicator))) {
        services.push(service);
      }
    });
    
    return [...new Set(services)]; // Remove duplicates
  }

  /**
   * Detect cloud API calls from script content
   */
  private detectCloudApis(content: string): CloudApi[] {
    const apis: CloudApi[] = [];
    
    // Azure API patterns
    const azureApiPatterns = [
      { service: 'Azure Storage', apiName: 'Blob Storage', operation: 'Get', indicators: ['get-azstorageblob', 'get-azstoragecontainer'] },
      { service: 'Azure Key Vault', apiName: 'Key Vault', operation: 'Get', indicators: ['get-azkeyvaultsecret', 'get-azkeyvault'] },
      { service: 'Azure Compute', apiName: 'Virtual Machines', operation: 'Get', indicators: ['get-azvm', 'get-azvmimage'] }
    ];
    
    // AWS API patterns
    const awsApiPatterns = [
      { service: 'AWS S3', apiName: 'S3', operation: 'Get', indicators: ['get-s3object', 'get-s3bucket'] },
      { service: 'AWS EC2', apiName: 'EC2', operation: 'Get', indicators: ['get-ec2instance', 'get-ec2image'] }
    ];
    
    // Check for Azure APIs
    azureApiPatterns.forEach(pattern => {
      if (pattern.indicators.some(indicator => content.includes(indicator))) {
        apis.push({
          service: pattern.service,
          apiName: pattern.apiName,
          operation: pattern.operation,
          indicators: pattern.indicators.filter(ind => content.includes(ind))
        });
      }
    });
    
    // Check for AWS APIs
    awsApiPatterns.forEach(pattern => {
      if (pattern.indicators.some(indicator => content.includes(indicator))) {
        apis.push({
          service: pattern.service,
          apiName: pattern.apiName,
          operation: pattern.operation,
          indicators: pattern.indicators.filter(ind => content.includes(ind))
        });
      }
    });
    
    return apis;
  }

  /**
   * Detect cloud resources from script content
   */
  private detectCloudResources(content: string): CloudResource[] {
    const resources: CloudResource[] = [];
    
    // Resource patterns
    const resourcePatterns = [
      { type: 'storage_account', indicators: ['storage account', 'storageaccount'], permissions: ['read', 'write'] },
      { type: 'virtual_machine', indicators: ['vm', 'virtual machine'], permissions: ['start', 'stop', 'restart'] },
      { type: 'database', indicators: ['database', 'sql database'], permissions: ['read', 'write'] },
      { type: 'key_vault', indicators: ['keyvault', 'key vault'], permissions: ['get', 'set'] }
    ];
    
    resourcePatterns.forEach(pattern => {
      const matchedIndicators = pattern.indicators.filter(ind => content.includes(ind));
      if (matchedIndicators.length > 0) {
        resources.push({
          type: pattern.type,
          permissions: pattern.permissions
        });
      }
    });
    
    return resources;
  }

  /**
   * Build metadata for the context
   */
  private buildMetadata(
    environmentType: ExecutionEnvironmentType,
    privilegeLevel: PrivilegeLevel,
    networkExposure: NetworkExposure,
    platform: CloudPlatform,
    content: string
  ): ContextMetadata {
    const assumptions: string[] = [];
    const detectedPatterns: string[] = [];
    
    // Build assumptions based on detected values
    if (platform === CloudPlatform.UNKNOWN) {
      assumptions.push('Cloud platform could not be determined from script content');
    } else {
      assumptions.push(`Script appears to target ${platform.toUpperCase()} platform`);
    }
    
    if (environmentType === ExecutionEnvironmentType.CLOUD_VM) {
      assumptions.push('Script likely runs in a cloud VM environment');
    }
    
    if (privilegeLevel === PrivilegeLevel.USER) {
      assumptions.push('Script runs with standard user privileges');
    } else if (privilegeLevel === PrivilegeLevel.ADMIN) {
      assumptions.push('Script requires or uses administrative privileges');
      detectedPatterns.push('Administrative privilege indicators detected');
    } else if (privilegeLevel === PrivilegeLevel.MANAGED_IDENTITY) {
      assumptions.push('Script uses managed identity for authentication');
      detectedPatterns.push('Managed identity authentication detected');
    }
    
    if (networkExposure === NetworkExposure.INTERNET_FACING) {
      assumptions.push('Script may access internet-facing resources');
      detectedPatterns.push('Network activity indicators detected');
    } else {
      assumptions.push('Script appears to only access internal resources');
    }
    
    // Calculate confidence based on detected patterns
    let confidence = 0.5; // Base confidence
    if (platform !== CloudPlatform.UNKNOWN) confidence += 0.2;
    if (detectedPatterns.length > 0) confidence += 0.2;
    if (content.length > 100) confidence += 0.1; // More content = more context
    
    confidence = Math.min(confidence, 1.0); // Cap at 1.0
    
    return {
      confidence,
      assumptions,
      detectedPatterns
    };
  }

  /**
   * Validate context for invalid combinations
   * 
   * Throws an error if invalid combinations are detected.
   */
  private validateContext(context: CloudExecutionContext): void {
    // Validate that all required fields are present
    if (!context.environmentType) {
      throw new Error('Invalid context: environmentType is required');
    }
    
    if (!context.privilegeLevel) {
      throw new Error('Invalid context: privilegeLevel is required');
    }
    
    if (!context.networkExposure) {
      throw new Error('Invalid context: networkExposure is required');
    }
    
    if (!context.platform) {
      throw new Error('Invalid context: platform is required');
    }
    
    // Validate enum values are valid
    if (!Object.values(ExecutionEnvironmentType).includes(context.environmentType)) {
      throw new Error(`Invalid context: unknown environmentType: ${context.environmentType}`);
    }
    
    if (!Object.values(PrivilegeLevel).includes(context.privilegeLevel)) {
      throw new Error(`Invalid context: unknown privilegeLevel: ${context.privilegeLevel}`);
    }
    
    if (!Object.values(NetworkExposure).includes(context.networkExposure)) {
      throw new Error(`Invalid context: unknown networkExposure: ${context.networkExposure}`);
    }
    
    if (!Object.values(CloudPlatform).includes(context.platform)) {
      throw new Error(`Invalid context: unknown platform: ${context.platform}`);
    }
    
    // Validate metadata
    if (!context.metadata) {
      throw new Error('Invalid context: metadata is required');
    }
    
    if (context.metadata.confidence < 0 || context.metadata.confidence > 1) {
      throw new Error(`Invalid context: metadata.confidence must be between 0 and 1, got ${context.metadata.confidence}`);
    }
    
    // All validations passed
  }

  /**
   * Get default context configuration
   * 
   * @returns Default cloud execution context
   */
  getDefaultContext(): CloudExecutionContext {
    return { ...DEFAULT_CONTEXT };
  }
}

// Legacy interface exports for backward compatibility
export interface ExecutionEnvironment {
  platform: CloudPlatform;
  assumptions: string[];
}
