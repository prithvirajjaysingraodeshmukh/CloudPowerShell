import { AnalysisFeatures } from '../../types/analysis';

// Suspicious PowerShell keywords and patterns
const SUSPICIOUS_KEYWORDS = [
  'iex', 'invoke-expression', 'invoke-command', 'invoke-item',
  'bypass', 'executionpolicy', 'noprofile', 'windowstyle', 'hidden',
  'downloadstring', 'downloadfile', 'webclient', 'net.webclient',
  'start-process', 'start-job', 'new-object', 'reflection.assembly',
  'system.convert', 'frombase64string', 'tobase64string',
  'compression.gzipstream', 'system.io.compression',
  'security.cryptography', 'aes', 'rijndael', 'des',
  'powershell.exe', 'cmd.exe', 'wscript', 'cscript',
  'regsvr32', 'rundll32', 'mshta', 'bitsadmin',
  'certutil', 'schtasks', 'at.exe', 'wmic',
  'vssadmin', 'bcdedit', 'diskpart', 'taskkill',
  'netsh', 'route', 'arp', 'ipconfig',
  'mimikatz', 'kerberoast', 'bloodhound', 'empire',
  'metasploit', 'cobalt', 'beacon', 'shellcode'
];

// PowerShell commands for analysis
const POWERSHELL_COMMANDS = [
  'get-process', 'get-service', 'get-wmiobject', 'get-childitem',
  'set-executionpolicy', 'invoke-webrequest', 'invoke-restmethod',
  'new-object', 'add-type', 'start-process', 'stop-process',
  'get-content', 'set-content', 'out-file', 'export-csv',
  'import-module', 'get-module', 'new-module', 'remove-module',
  'get-command', 'get-help', 'get-member', 'where-object',
  'foreach-object', 'select-object', 'sort-object', 'group-object',
  'measure-object', 'compare-object', 'tee-object', 'format-table',
  'format-list', 'out-gridview', 'out-string', 'convertto-json',
  'convertfrom-json', 'convertto-xml', 'convertfrom-xml'
];

// Encoding methods
const ENCODING_METHODS = [
  'base64', 'utf8', 'unicode', 'ascii', 'utf7', 'utf32',
  'gzip', 'deflate', 'compress', 'decompress',
  'encrypt', 'decrypt', 'encode', 'decode',
  'tobase64string', 'frombase64string'
];

// File extensions commonly targeted
const SUSPICIOUS_EXTENSIONS = [
  '.exe', '.dll', '.bat', '.cmd', '.ps1', '.vbs', '.js',
  '.jar', '.scr', '.com', '.pif', '.msi', '.reg'
];

/**
 * Static Analysis Engine
 * 
 * Performs static analysis of PowerShell scripts to extract features,
 * detect obfuscation, and identify suspicious patterns.
 */
export class StaticAnalysisEngine {
  /**
   * Calculate Shannon entropy of text
   */
  calculateEntropy(text: string): number {
    const frequency: { [key: string]: number } = {};
    const length = text.length;
    
    // Count character frequencies
    for (const char of text) {
      frequency[char] = (frequency[char] || 0) + 1;
    }
    
    // Calculate entropy
    let entropy = 0;
    for (const char in frequency) {
      const p = frequency[char] / length;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  /**
   * Detect Base64 encoded strings
   */
  detectBase64Strings(text: string): string[] {
    const base64Regex = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const matches = text.match(base64Regex) || [];
    
    return matches.filter(match => {
      // Additional validation for Base64
      try {
        // Check if it's valid Base64 and not just random alphanumeric
        const decoded = atob(match);
        return decoded.length > 10 && /[a-zA-Z]/.test(decoded);
      } catch {
        return false;
      }
    });
  }

  /**
   * Extract URLs from script
   */
  extractUrls(text: string): string[] {
    const urlRegex = /https?:\/\/[^\s<>"']+/gi;
    return text.match(urlRegex) || [];
  }

  /**
   * Extract IP addresses
   */
  extractIpAddresses(text: string): string[] {
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g;
    const matches = text.match(ipRegex) || [];
    return matches.filter(ip => {
      const parts = ip.split('.');
      return parts.every(part => parseInt(part) <= 255);
    });
  }

  /**
   * Detect file extensions
   */
  detectFileExtensions(text: string): string[] {
    const extensionRegex = /\.[a-zA-Z0-9]{2,4}\b/g;
    const matches = text.match(extensionRegex) || [];
    const uniqueExtensions = [...new Set(matches.map(ext => ext.toLowerCase()))];
    return uniqueExtensions.filter(ext => SUSPICIOUS_EXTENSIONS.includes(ext));
  }

  /**
   * Find PowerShell commands
   */
  findPowershellCommands(text: string): string[] {
    const lowerText = text.toLowerCase();
    return POWERSHELL_COMMANDS.filter(cmd => 
      lowerText.includes(cmd.toLowerCase())
    );
  }

  /**
   * Detect encoding methods
   */
  detectEncodingMethods(text: string): string[] {
    const lowerText = text.toLowerCase();
    return ENCODING_METHODS.filter(method => 
      lowerText.includes(method.toLowerCase())
    );
  }

  /**
   * Analyze string obfuscation techniques
   */
  analyzeStringObfuscation(text: string): string[] {
    const techniques = [];
    
    // String concatenation
    if (text.includes('+') && /['"][^'"]*['"]\s*\+\s*['"][^'"]*['"]/.test(text)) {
      techniques.push('String Concatenation');
    }
    
    // Character replacement
    if (/`[a-zA-Z]/.test(text)) {
      techniques.push('Backtick Obfuscation');
    }
    
    // Variable substitution in strings
    if (/\$\{[^}]+\}/.test(text)) {
      techniques.push('Variable Substitution');
    }
    
    // Format strings
    if (/-f\s*@\(/.test(text)) {
      techniques.push('Format String Obfuscation');
    }
    
    // Character arrays
    if (/\[char\[\]\]/.test(text)) {
      techniques.push('Character Array Conversion');
    }
    
    return techniques;
  }

  /**
   * Calculate variable obfuscation score
   */
  calculateVariableObfuscationScore(text: string): number {
    const variables = text.match(/\$[a-zA-Z_][a-zA-Z0-9_`]*/g) || [];
    if (variables.length === 0) return 0;
    
    let obfuscatedCount = 0;
    const uniqueVars = [...new Set(variables)];
    
    uniqueVars.forEach(variable => {
      const varName = variable.substring(1); // Remove $
      
      // Check for obfuscation patterns
      if (varName.length < 3 && /[A-Z]{2,}/.test(varName)) obfuscatedCount++;
      if (/[`]/.test(varName)) obfuscatedCount++;
      if (/^[a-zA-Z]{1,2}[0-9]{2,}$/.test(varName)) obfuscatedCount++;
      if (varName.length > 20 && !/[aeiou]/i.test(varName)) obfuscatedCount++;
    });
    
    return Math.min((obfuscatedCount / uniqueVars.length) * 100, 100);
  }

  /**
   * Calculate comment ratio
   */
  calculateCommentRatio(text: string): number {
    const lines = text.split('\n');
    const commentLines = lines.filter(line => line.trim().startsWith('#')).length;
    return lines.length > 0 ? (commentLines / lines.length) * 100 : 0;
  }

  /**
   * Count functions
   */
  countFunctions(text: string): number {
    const functionRegex = /function\s+[a-zA-Z_][a-zA-Z0-9_-]*\s*\{/gi;
    return (text.match(functionRegex) || []).length;
  }

  /**
   * Calculate nested block depth
   */
  calculateNestedBlockDepth(text: string): number {
    let maxDepth = 0;
    let currentDepth = 0;
    
    for (const char of text) {
      if (char === '{') {
        currentDepth++;
        maxDepth = Math.max(maxDepth, currentDepth);
      } else if (char === '}') {
        currentDepth = Math.max(0, currentDepth - 1);
      }
    }
    
    return maxDepth;
  }

  /**
   * Find suspicious keywords
   */
  findSuspiciousKeywords(text: string): string[] {
    const lowerText = text.toLowerCase();
    return SUSPICIOUS_KEYWORDS.filter(keyword => 
      lowerText.includes(keyword.toLowerCase())
    );
  }

  /**
   * Calculate maximum string length
   */
  getMaxStringLength(text: string): number {
    const stringMatches = text.match(/"[^"]*"|'[^']*'/g) || [];
    return Math.max(0, ...stringMatches.map(s => s.length - 2)); // -2 for quotes
  }

  /**
   * Calculate obfuscation score
   */
  calculateObfuscationScore(features: AnalysisFeatures): number {
    let score = 0;
    
    // High entropy indicates obfuscation
    if (features.entropy > 6) score += 30;
    else if (features.entropy > 5) score += 20;
    else if (features.entropy > 4) score += 10;
    
    // Base64 strings indicate encoding
    score += Math.min(features.base64Count * 15, 40);
    
    // Long strings might be encoded payloads
    if (features.maxStringLength > 1000) score += 25;
    else if (features.maxStringLength > 500) score += 15;
    else if (features.maxStringLength > 200) score += 10;
    
    // Suspicious keywords
    score += Math.min(features.suspiciousKeywordCount * 10, 50);
    
    // Very long scripts might be padded or contain large payloads
    if (features.totalLength > 50000) score += 15;
    else if (features.totalLength > 20000) score += 10;
    
    // Short average line length with high entropy suggests obfuscation
    if (features.averageLineLength < 50 && features.entropy > 5) score += 15;
    
    // New scoring factors
    score += Math.min(features.urlCount * 5, 20);
    score += Math.min(features.ipCount * 8, 25);
    score += Math.min(features.encodingMethodCount * 12, 30);
    score += Math.min(features.variableObfuscationScore * 0.3, 20);
    score += Math.min(features.nestedBlockDepth * 3, 15);
    
    // Low comment ratio in complex scripts is suspicious
    if (features.totalLength > 1000 && features.commentRatio < 5) score += 10;
    
    return Math.min(score, 100);
  }

  /**
   * Generate threat categories
   */
  generateThreatCategories(features: AnalysisFeatures): string[] {
    const categories = [];
    
    if (features.base64Count > 3) categories.push('Encoded Payload');
    if (features.urlCount > 0) categories.push('Network Communication');
    if (features.ipCount > 0) categories.push('Direct IP Communication');
    if (features.suspiciousKeywordCount > 5) categories.push('Execution Policy Bypass');
    if (features.variableObfuscationScore > 50) categories.push('Code Obfuscation');
    if (features.entropy > 6) categories.push('High Entropy Content');
    if (features.encodingMethodCount > 2) categories.push('Multiple Encoding Methods');
    if (features.nestedBlockDepth > 5) categories.push('Complex Control Flow');
    
    return categories;
  }

  /**
   * Generate risk factors
   */
  generateRiskFactors(features: AnalysisFeatures, _scriptContent: string): any[] {
    const riskFactors = [];
    
    if (features.base64Count > 0) {
      riskFactors.push({
        category: 'Encoded Content',
        severity: features.base64Count > 5 ? 'high' : features.base64Count > 2 ? 'medium' : 'low',
        description: `Found ${features.base64Count} Base64 encoded string(s)`,
        evidence: features.base64Strings.slice(0, 3).map(s => s.substring(0, 50) + '...')
      });
    }
    
    if (features.urlCount > 0) {
      riskFactors.push({
        category: 'Network Activity',
        severity: features.urlCount > 3 ? 'critical' : features.urlCount > 1 ? 'high' : 'medium',
        description: `Script contains ${features.urlCount} URL(s)`,
        evidence: features.urlsFound
      });
    }
    
    if (features.suspiciousKeywordCount > 0) {
      riskFactors.push({
        category: 'Suspicious Commands',
        severity: features.suspiciousKeywordCount > 10 ? 'critical' : features.suspiciousKeywordCount > 5 ? 'high' : 'medium',
        description: `Contains ${features.suspiciousKeywordCount} suspicious keyword(s)`,
        evidence: features.suspiciousKeywords.slice(0, 5)
      });
    }
    
    if (features.variableObfuscationScore > 30) {
      riskFactors.push({
        category: 'Code Obfuscation',
        severity: features.variableObfuscationScore > 70 ? 'high' : 'medium',
        description: `High variable obfuscation score: ${features.variableObfuscationScore.toFixed(1)}%`,
        evidence: ['Obfuscated variable names detected']
      });
    }
    
    return riskFactors;
  }

  /**
   * Generate recommendations
   */
  generateRecommendations(features: AnalysisFeatures, classification: string): string[] {
    const recommendations = [];
    
    if (classification === 'malicious') {
      recommendations.push('🚨 DO NOT EXECUTE this script - it shows strong indicators of malicious activity');
      recommendations.push('🔒 Quarantine the file immediately');
      recommendations.push('🔍 Perform deeper analysis in an isolated environment');
    } else if (classification === 'suspicious') {
      recommendations.push('⚠️ Exercise extreme caution before executing');
      recommendations.push('🧪 Test in a sandboxed environment first');
      recommendations.push('👀 Review the script manually for legitimacy');
    }
    
    if (features.base64Count > 0) {
      recommendations.push('🔓 Decode Base64 strings to understand their purpose');
    }
    
    if (features.urlCount > 0) {
      recommendations.push('🌐 Verify all URLs are from trusted sources');
      recommendations.push('📡 Monitor network traffic if execution is necessary');
    }
    
    if (features.variableObfuscationScore > 50) {
      recommendations.push('🔍 Deobfuscate variable names for better analysis');
    }
    
    if (features.commentRatio < 10 && features.totalLength > 1000) {
      recommendations.push('📝 Low comment ratio suggests potential obfuscation');
    }
    
    return recommendations;
  }

  /**
   * Perform YARA-like rule matching
   */
  performYaraAnalysis(scriptContent: string): any[] {
    const matches = [];
    const lowerContent = scriptContent.toLowerCase();
    
    // PowerShell Empire detection
    if (lowerContent.includes('invoke-empire') || lowerContent.includes('empire.ps1')) {
      matches.push({
        ruleName: 'PowerShell_Empire',
        description: 'Detects PowerShell Empire framework usage',
        severity: 'critical',
        tags: ['apt', 'post-exploitation', 'empire'],
        matches: ['invoke-empire', 'empire.ps1']
      });
    }
    
    // Mimikatz detection
    if (lowerContent.includes('mimikatz') || lowerContent.includes('sekurlsa')) {
      matches.push({
        ruleName: 'Mimikatz_Usage',
        description: 'Detects Mimikatz credential dumping tool',
        severity: 'critical',
        tags: ['credential-theft', 'mimikatz', 'post-exploitation'],
        matches: ['mimikatz', 'sekurlsa']
      });
    }
    
    // Cobalt Strike detection
    if (lowerContent.includes('beacon') || lowerContent.includes('cobalt')) {
      matches.push({
        ruleName: 'Cobalt_Strike',
        description: 'Detects Cobalt Strike beacon activity',
        severity: 'critical',
        tags: ['apt', 'cobalt-strike', 'c2'],
        matches: ['beacon', 'cobalt']
      });
    }
    
    // Fileless malware detection
    if (lowerContent.includes('reflectiveloader') || lowerContent.includes('invoke-reflectivedllinjection')) {
      matches.push({
        ruleName: 'Fileless_Malware',
        description: 'Detects fileless malware techniques',
        severity: 'high',
        tags: ['fileless', 'injection', 'evasion'],
        matches: ['reflectiveloader', 'invoke-reflectivedllinjection']
      });
    }
    
    // Persistence mechanisms
    if (lowerContent.includes('new-scheduledtask') || lowerContent.includes('schtasks')) {
      matches.push({
        ruleName: 'Persistence_Scheduled_Task',
        description: 'Detects scheduled task persistence',
        severity: 'medium',
        tags: ['persistence', 'scheduled-task'],
        matches: ['new-scheduledtask', 'schtasks']
      });
    }
    
    return matches;
  }

  /**
   * Analyze behavior patterns
   */
  analyzeBehavior(scriptContent: string): any {
    const lowerContent = scriptContent.toLowerCase();
    
    return {
      fileOperations: this.extractFileOperations(lowerContent),
      registryOperations: this.extractRegistryOperations(lowerContent),
      networkConnections: this.extractNetworkConnections(lowerContent),
      processCreation: this.extractProcessCreation(lowerContent),
      serviceManipulation: this.extractServiceManipulation(lowerContent),
      scheduledTasks: this.extractScheduledTasks(lowerContent),
      persistenceMechanisms: this.extractPersistenceMechanisms(lowerContent),
      antiAnalysis: this.extractAntiAnalysis(lowerContent),
      dataExfiltration: this.extractDataExfiltration(lowerContent),
      privilegeEscalation: this.extractPrivilegeEscalation(lowerContent)
    };
  }

  private extractFileOperations(content: string): string[] {
    const operations = [];
    if (content.includes('new-item')) operations.push('File Creation');
    if (content.includes('remove-item')) operations.push('File Deletion');
    if (content.includes('copy-item')) operations.push('File Copy');
    if (content.includes('move-item')) operations.push('File Move');
    if (content.includes('get-content')) operations.push('File Read');
    if (content.includes('set-content')) operations.push('File Write');
    return operations;
  }

  private extractRegistryOperations(content: string): string[] {
    const operations = [];
    if (content.includes('new-itemproperty')) operations.push('Registry Key Creation');
    if (content.includes('remove-itemproperty')) operations.push('Registry Key Deletion');
    if (content.includes('set-itemproperty')) operations.push('Registry Value Modification');
    if (content.includes('get-itemproperty')) operations.push('Registry Value Read');
    return operations;
  }

  private extractNetworkConnections(content: string): string[] {
    const connections = [];
    if (content.includes('invoke-webrequest')) connections.push('HTTP Request');
    if (content.includes('invoke-restmethod')) connections.push('REST API Call');
    if (content.includes('new-object system.net.webclient')) connections.push('WebClient Usage');
    if (content.includes('test-netconnection')) connections.push('Network Connectivity Test');
    return connections;
  }

  private extractProcessCreation(content: string): string[] {
    const processes = [];
    if (content.includes('start-process')) processes.push('Process Start');
    if (content.includes('invoke-expression')) processes.push('Dynamic Code Execution');
    if (content.includes('invoke-command')) processes.push('Remote Command Execution');
    return processes;
  }

  private extractServiceManipulation(content: string): string[] {
    const services = [];
    if (content.includes('new-service')) services.push('Service Creation');
    if (content.includes('stop-service')) services.push('Service Stop');
    if (content.includes('start-service')) services.push('Service Start');
    if (content.includes('set-service')) services.push('Service Modification');
    return services;
  }

  private extractScheduledTasks(content: string): string[] {
    const tasks = [];
    if (content.includes('new-scheduledtask')) tasks.push('Scheduled Task Creation');
    if (content.includes('register-scheduledtask')) tasks.push('Scheduled Task Registration');
    if (content.includes('schtasks')) tasks.push('Legacy Scheduled Task');
    return tasks;
  }

  private extractPersistenceMechanisms(content: string): string[] {
    const mechanisms = [];
    if (content.includes('hklm:\\software\\microsoft\\windows\\currentversion\\run')) mechanisms.push('Registry Run Key');
    if (content.includes('startup')) mechanisms.push('Startup Folder');
    if (content.includes('wmi')) mechanisms.push('WMI Event Subscription');
    return mechanisms;
  }

  private extractAntiAnalysis(content: string): string[] {
    const techniques = [];
    if (content.includes('get-process') && content.includes('wireshark')) techniques.push('Network Analysis Detection');
    if (content.includes('get-process') && content.includes('procmon')) techniques.push('Process Monitor Detection');
    if (content.includes('sleep') || content.includes('start-sleep')) techniques.push('Delay Execution');
    if (content.includes('test-path') && content.includes('sandbox')) techniques.push('Sandbox Detection');
    return techniques;
  }

  private extractDataExfiltration(content: string): string[] {
    const methods = [];
    if (content.includes('compress-archive')) methods.push('Data Compression');
    if (content.includes('send-mailmessage')) methods.push('Email Exfiltration');
    if (content.includes('ftp')) methods.push('FTP Upload');
    if (content.includes('invoke-webrequest') && content.includes('post')) methods.push('HTTP POST Exfiltration');
    return methods;
  }

  private extractPrivilegeEscalation(content: string): string[] {
    const techniques = [];
    if (content.includes('runas')) techniques.push('RunAs Execution');
    if (content.includes('uac')) techniques.push('UAC Bypass');
    if (content.includes('token')) techniques.push('Token Manipulation');
    return techniques;
  }

  /**
   * Generate timeline analysis
   */
  generateTimeline(scriptContent: string): Array<{
    timestamp: string;
    action: string;
    description: string;
    severity: 'info' | 'warning' | 'critical';
    lineNumber?: number;
  }> {
    const timeline: Array<{
      timestamp: string;
      action: string;
      description: string;
      severity: 'info' | 'warning' | 'critical';
      lineNumber?: number;
    }> = [];
    const lines = scriptContent.split('\n');
    
    lines.forEach((line, index) => {
      const lowerLine = line.toLowerCase().trim();
      if (lowerLine.includes('invoke-webrequest') || lowerLine.includes('downloadstring')) {
        timeline.push({
          timestamp: `Line ${index + 1}`,
          action: 'Network Request',
          description: 'Script attempts to download content from remote server',
          severity: 'warning',
          lineNumber: index + 1
        });
      }
      
      if (lowerLine.includes('start-process') || lowerLine.includes('invoke-expression')) {
        timeline.push({
          timestamp: `Line ${index + 1}`,
          action: 'Code Execution',
          description: 'Script executes external code or process',
          severity: 'critical',
          lineNumber: index + 1
        });
      }
      
      if (lowerLine.includes('new-item') && lowerLine.includes('.exe')) {
        timeline.push({
          timestamp: `Line ${index + 1}`,
          action: 'File Creation',
          description: 'Script creates executable file',
          severity: 'warning',
          lineNumber: index + 1
        });
      }
    });
    
    return timeline;
  }

  /**
   * Analyze script and extract all features
   */
  analyze(scriptContent: string): {
    features: AnalysisFeatures;
    threatCategories: string[];
    riskFactors: any[];
    recommendations: string[];
    yara: any[];
    behaviorAnalysis: any;
    timeline: any[];
  } {
    const lines = scriptContent.split('\n');
    
    const features: AnalysisFeatures = {
      entropy: this.calculateEntropy(scriptContent),
      base64Strings: this.detectBase64Strings(scriptContent),
      base64Count: 0,
      maxStringLength: this.getMaxStringLength(scriptContent),
      suspiciousKeywords: this.findSuspiciousKeywords(scriptContent),
      suspiciousKeywordCount: 0,
      totalLength: scriptContent.length,
      lineCount: lines.length,
      averageLineLength: scriptContent.length / lines.length,
      obfuscationScore: 0,
      urlsFound: this.extractUrls(scriptContent),
      urlCount: 0,
      ipAddresses: this.extractIpAddresses(scriptContent),
      ipCount: 0,
      fileExtensions: this.detectFileExtensions(scriptContent),
      fileExtensionCount: 0,
      powershellCommands: this.findPowershellCommands(scriptContent),
      powershellCommandCount: 0,
      encodingMethods: this.detectEncodingMethods(scriptContent),
      encodingMethodCount: 0,
      stringObfuscationTechniques: this.analyzeStringObfuscation(scriptContent),
      variableObfuscationScore: this.calculateVariableObfuscationScore(scriptContent),
      commentRatio: this.calculateCommentRatio(scriptContent),
      functionCount: this.countFunctions(scriptContent),
      nestedBlockDepth: this.calculateNestedBlockDepth(scriptContent)
    };
    
    features.base64Count = features.base64Strings.length;
    features.suspiciousKeywordCount = features.suspiciousKeywords.length;
    features.urlCount = features.urlsFound.length;
    features.ipCount = features.ipAddresses.length;
    features.fileExtensionCount = features.fileExtensions.length;
    features.powershellCommandCount = features.powershellCommands.length;
    features.encodingMethodCount = features.encodingMethods.length;
    features.obfuscationScore = this.calculateObfuscationScore(features);
    
    // Simple classification based on heuristics
    let classification: 'benign' | 'suspicious' | 'malicious';
    if (features.obfuscationScore >= 75) {
      classification = 'malicious';
    } else if (features.obfuscationScore >= 45) {
      classification = 'suspicious';
    } else {
      classification = 'benign';
    }
    
    return {
      features,
      threatCategories: this.generateThreatCategories(features),
      riskFactors: this.generateRiskFactors(features, scriptContent),
      recommendations: this.generateRecommendations(features, classification),
      yara: this.performYaraAnalysis(scriptContent),
      behaviorAnalysis: this.analyzeBehavior(scriptContent),
      timeline: this.generateTimeline(scriptContent)
    };
  }
}

