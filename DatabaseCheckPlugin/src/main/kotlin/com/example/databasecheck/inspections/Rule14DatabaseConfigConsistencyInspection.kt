/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
 
package com.example.databasecheck.inspections

import com.example.databasecheck.utils.DatabaseConstants
import com.intellij.codeInspection.*
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiFile

/**
 * Rule 14: Database Configuration Consistency
 *
 * This inspection detects violations of HarmonyOS Database Robustness Rule 14, which requires
 * that database configuration parameters remain consistent across all getRdbStore calls
 * for the same database name within a HAP package.
 *
 * ## Rule Requirements:
 * For the same database name, all getRdbStore calls must use identical configuration parameters:
 * - `name` - Database name (must be identical)
 * - `securityLevel` - Security level setting  
 * - `encrypt` - Encryption setting
 * - `isReadOnly` - Read-only mode setting
 * - `customDir` - Custom directory setting
 *
 * ## Detected Violations:
 * - Different securityLevel values for same database name
 * - Inconsistent encrypt settings (true/false or presence/absence)
 * - Varying isReadOnly settings for same database
 * - Different customDir values for same database name
 * - Mixed configuration approaches (object literals vs variables)
 *
 * ## Positive Example (Consistent):
 * ```javascript
 * const CONFIG = {
 *     "name": STORE_NAME,
 *     securityLevel: relationalStore.SecurityLevel.S3
 * }
 * 
 * async function CreateRdbStore(context) {
 *     return await relationalStore.getRdbStore(context, CONFIG);
 * }
 * 
 * async function GetActiveRdbStore(context) {
 *     return await relationalStore.getRdbStore(context, CONFIG);
 * }
 * ```
 *
 * ## Negative Example (Inconsistent):
 * ```javascript
 * async function CreateRdbStore(context) {
 *     const config = {
 *         "name": STORE_NAME,
 *         securityLevel: relationalStore.SecurityLevel.S3
 *     }
 *     return await relationalStore.getRdbStore(context, config);
 * }
 * 
 * async function GetActiveRdbStore(context) {
 *     const config = {
 *         "name": STORE_NAME,
 *         securityLevel: relationalStore.SecurityLevel.S3,
 *         encrypt: true,        // Added parameter
 *         isReadOnly: true      // Added parameter  
 *     }
 *     return await relationalStore.getRdbStore(context, config);
 * }
 * ```
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule14DatabaseConfigConsistencyInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "Database Configuration Consistency"
    override fun getRuleNumber(): Int = 14
    override fun getDescription(): String =
        "Ensures consistent database configuration parameters across all getRdbStore calls for the same database name."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }

    /**
     * Main analysis logic for detecting database configuration inconsistencies
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        val originalText = file.text
        if (originalText.isBlank()) return

        try {
            // Step 0: Remove comments to avoid parsing interference
            val codeText = removeComments(originalText)
            
            // Find all getRdbStore calls and extract configurations
            val rdbStoreCalls = findGetRdbStoreCalls(codeText)
            
            // Group configurations by database name
            val configsByName = groupConfigurationsByDatabaseName(rdbStoreCalls)
            
            // Detect inconsistencies within each database name group
            val violations = detectConfigurationInconsistencies(configsByName)
            
            // Report all violations
            violations.forEach { violation ->
                reportViolation(violation, file, holder, originalText)
            }
            
        } catch (e: Exception) {
            // Fallback analysis if main analysis fails
            fallbackConfigAnalysis(file, holder)
        }
    }

    /**
     * Find all getRdbStore calls and extract their configurations
     */
    private fun findGetRdbStoreCalls(codeText: String): List<RdbStoreCall> {
        val calls = mutableListOf<RdbStoreCall>()
        
        // Find getRdbStore calls with proper multi-line support
        val getRdbStorePattern = Regex("""getRdbStore\s*\(""", RegexOption.MULTILINE)
        val matches = getRdbStorePattern.findAll(codeText).toList()
        
        matches.forEach { match ->
            val startPos = match.range.first
            
            // Find the complete call by parsing from the match position
            val callInfo = extractCompleteCall(codeText, startPos)
            
            if (callInfo != null) {
                val config = extractConfiguration(callInfo.configParam, codeText, callInfo.startOffset)
                
                if (config != null) {
                    calls.add(
                        RdbStoreCall(
                            configParameter = callInfo.configParam,
                            configuration = config,
                            startOffset = callInfo.startOffset,
                            endOffset = callInfo.endOffset,
                            fullMatch = callInfo.fullMatch
                        )
                    )
                }
            }
        }
        
        return calls
    }
    
    /**
     * Extract complete getRdbStore call from starting position
     */
    private fun extractCompleteCall(codeText: String, startPos: Int): CallInfo? {
        var pos = startPos
        
        // Skip "getRdbStore" and whitespace
        while (pos < codeText.length && codeText[pos] != '(') pos++
        if (pos >= codeText.length) return null
        
        pos++ // Skip '('
        var parenCount = 1
        var commaPos = -1
        val callStart = startPos
        
        // Find the comma separating context and config parameters
        var tempPos = pos
        while (tempPos < codeText.length && parenCount > 0) {
            when (codeText[tempPos]) {
                '(' -> parenCount++
                ')' -> parenCount--
                ',' -> if (parenCount == 1 && commaPos == -1) commaPos = tempPos
            }
            tempPos++
        }
        
        if (commaPos == -1 || parenCount != 0) return null
        
        val configStart = commaPos + 1
        val callEnd = tempPos - 1
        
        val configParam = codeText.substring(configStart, callEnd).trim()
        val fullMatch = codeText.substring(callStart, tempPos)
        
        return CallInfo(configParam, callStart, tempPos, fullMatch)
    }
    
    private data class CallInfo(
        val configParam: String,
        val startOffset: Int,
        val endOffset: Int,
        val fullMatch: String
    )

    /**
     * Extract configuration details from the parameter
     */
    private fun extractConfiguration(configParam: String, codeText: String, callPosition: Int): DatabaseConfiguration? {
        val trimmedParam = configParam.trim()
        
        // Method 1: Direct object literal (starts with {)
        if (trimmedParam.startsWith("{")) {
            return parseObjectLiteral(trimmedParam)
        }
        
        // Method 2: Variable reference (simple identifier)
        if (trimmedParam.matches(Regex("""[a-zA-Z_$][a-zA-Z0-9_$]*"""))) {
            return findVariableConfiguration(trimmedParam, codeText, callPosition)
        }
        
        return null
    }

    /**
     * Parse object literal configuration - extract all parameters
     */
    private fun parseObjectLiteral(objectLiteral: String): DatabaseConfiguration? {
        val config = DatabaseConfiguration()
        
        // Parse all key-value pairs in the object literal
        val parameterPattern = Regex("""(?:^|,)\s*(?:"([^"]+)"|'([^']+)'|([a-zA-Z_$][a-zA-Z0-9_$]*?))\s*:\s*([^,}]+)""", RegexOption.MULTILINE)
        
        parameterPattern.findAll(objectLiteral).forEach { match ->
            // Get the key name (could be in group 1, 2, or 3 depending on quote type)
            val key = when {
                match.groupValues[1].isNotEmpty() -> match.groupValues[1] // "key"
                match.groupValues[2].isNotEmpty() -> match.groupValues[2] // 'key'
                match.groupValues[3].isNotEmpty() -> match.groupValues[3] // key
                else -> return@forEach
            }
            
            val value = match.groupValues[4].trim()
            
            // Store in allParameters map
            config.allParameters[key] = value
            
            // Also store in specific fields for backward compatibility
            when (key) {
                "name" -> {
                    config.name = if (value.startsWith("\"") || value.startsWith("'")) {
                        value.removeSurrounding("\"", "'")
                    } else {
                        value // Keep variable names as-is (e.g., STORE_NAME)
                    }
                }
                "securityLevel" -> config.securityLevel = value
                "encrypt" -> config.encrypt = value
                "isReadOnly" -> config.isReadOnly = value
                "customDir" -> config.customDir = value.removeSurrounding("\"", "'")
            }
        }
        
        return if (config.name != null) config else null
    }

    /**
     * Find configuration from variable assignment - improved scope-aware search
     */
    private fun findVariableConfiguration(variableName: String, codeText: String, callPosition: Int): DatabaseConfiguration? {
        // Find all variable assignments for this name
        val pattern = Regex("""(?:const|let|var)\s+${Regex.escape(variableName)}\s*=\s*(\{[\s\S]*?})""", RegexOption.MULTILINE)
        val matches = pattern.findAll(codeText).toList()
        
        // Find the closest assignment before the call position
        var bestMatch: MatchResult? = null
        var bestDistance = Int.MAX_VALUE
        
        for (match in matches) {
            val assignmentPos = match.range.first
            
            if (assignmentPos < callPosition) {
                val distance = callPosition - assignmentPos
                if (distance < bestDistance) {
                    bestDistance = distance
                    bestMatch = match
                }
            }
        }
        
        if (bestMatch != null) {
            val objectLiteral = bestMatch.groupValues[1]
            return parseObjectLiteral(objectLiteral)
        }
        
        return null
    }

    /**
     * Group configurations by database name
     */
    private fun groupConfigurationsByDatabaseName(calls: List<RdbStoreCall>): Map<String, List<RdbStoreCall>> {
        return calls
            .filter { it.configuration?.name != null }
            .groupBy { it.configuration!!.name!! }
    }

    /**
     * Detect configuration inconsistencies within each database name group
     */
    private fun detectConfigurationInconsistencies(
        configsByName: Map<String, List<RdbStoreCall>>
    ): List<ConfigurationViolation> {
        val violations = mutableListOf<ConfigurationViolation>()
        
        for ((databaseName, calls) in configsByName) {
            if (calls.size <= 1) continue // No inconsistency possible with single call
            
            // Compare all configurations for this database name
            val referenceConfig = calls[0].configuration!!
            
            for (i in 1 until calls.size) {
                val currentCall = calls[i]
                val currentConfig = currentCall.configuration!!
                
                val inconsistencies = findInconsistencies(referenceConfig, currentConfig)
                
                if (inconsistencies.isNotEmpty()) {
                    violations.add(
                        ConfigurationViolation(
                            databaseName = databaseName,
                            inconsistentCall = currentCall,
                            referenceCall = calls[0],
                            inconsistentParameters = inconsistencies,
                            reason = "Database configuration inconsistency detected for '$databaseName'. " +
                                    "Parameters ${inconsistencies.joinToString(", ")} differ from previous configuration. " +
                                    "All getRdbStore calls for the same database name must use identical configuration parameters."
                        )
                    )
                }
            }
        }
        
        return violations
    }

    /**
     * Find inconsistencies between two configurations by comparing all parameters
     */
    private fun findInconsistencies(reference: DatabaseConfiguration, current: DatabaseConfiguration): List<String> {
        val inconsistencies = mutableListOf<String>()
        
        // Get all parameter names from both configurations
        val allParameters = getAllParameterNames(reference, current)
        
        for (paramName in allParameters) {
            val refValue = getParameterValue(reference, paramName)
            val curValue = getParameterValue(current, paramName)
            
            if (!areParametersEqual(refValue, curValue)) {
                inconsistencies.add(paramName)
            }
        }
        
        return inconsistencies
    }
    
    /**
     * Get all parameter names present in either configuration
     */
    private fun getAllParameterNames(config1: DatabaseConfiguration, config2: DatabaseConfiguration): Set<String> {
        val allParams = mutableSetOf<String>()
        
        // Add parameters from first configuration
        addParametersFromConfig(allParams, config1)
        
        // Add parameters from second configuration  
        addParametersFromConfig(allParams, config2)
        
        // Remove 'name' as it should always be the same for grouped configurations
        allParams.remove("name")
        
        return allParams
    }
    
    /**
     * Add parameter names from a configuration to the set
     */
    private fun addParametersFromConfig(paramSet: MutableSet<String>, config: DatabaseConfiguration) {
        // Add all parameters from the allParameters map
        paramSet.addAll(config.allParameters.keys)
    }
    
    /**
     * Get parameter value from configuration by name
     */
    private fun getParameterValue(config: DatabaseConfiguration, paramName: String): String? {
        // First check the allParameters map, then fall back to specific fields
        return config.allParameters[paramName] ?: when (paramName) {
            "securityLevel" -> config.securityLevel
            "encrypt" -> config.encrypt
            "isReadOnly" -> config.isReadOnly
            "customDir" -> config.customDir
            else -> null
        }
    }

    /**
     * Compare two parameter values, treating null and missing values as different from present values
     */
    private fun areParametersEqual(reference: String?, current: String?): Boolean {
        // Both null/missing - consistent
        if (reference == null && current == null) return true
        
        // One is null, other is not - inconsistent
        if (reference == null || current == null) return false
        
        // Both have values - compare them
        return reference == current
    }

    /**
     * Report a configuration violation
     */
    private fun reportViolation(violation: ConfigurationViolation, file: PsiFile, holder: ProblemsHolder, originalText: String) {
        val call = violation.inconsistentCall
        
        // Map the position from filtered code back to original code
        val mappedPosition = mapPositionToOriginal(call.startOffset, originalText)
        
        if (mappedPosition != -1) {
            // Find the getRdbStore call around the mapped position in original text
            val getRdbStorePattern = Regex("""getRdbStore\s*\(""", RegexOption.MULTILINE)
            val matches = getRdbStorePattern.findAll(originalText).toList()
            
            // Find the closest match to our mapped position
            val closestMatch = matches.minByOrNull { match -> 
                kotlin.math.abs(match.range.first - mappedPosition)
            }
            
            if (closestMatch != null) {
                val textRange = TextRange(closestMatch.range.first, closestMatch.range.last + 1)
                
                if (textRange.startOffset >= 0 && textRange.endOffset <= file.textLength && 
                    textRange.startOffset < textRange.endOffset) {
                    
                    createProblemDescriptor(
                        file, 
                        violation.reason,
                        holder,
                        textRange
                    )
                }
            }
        }
    }
    
    /**
     * Map position from comment-filtered code back to original code
     */
    private fun mapPositionToOriginal(filteredPosition: Int, originalText: String): Int {
        // Simple approximation: find the nth occurrence of "getRdbStore" 
        // This is not perfect but should work for most cases
        val getRdbStorePattern = Regex("""getRdbStore""", RegexOption.MULTILINE)
        val matches = getRdbStorePattern.findAll(originalText).toList()
        
        // For now, we'll use a simple heuristic: 
        // count how many getRdbStore occurrences come before filteredPosition in filtered text
        val filteredText = removeComments(originalText)
        val filteredMatches = getRdbStorePattern.findAll(filteredText).toList()
        
        // Find which getRdbStore call this position corresponds to
        var callIndex = 0
        for ((index, match) in filteredMatches.withIndex()) {
            if (match.range.first <= filteredPosition) {
                callIndex = index
            } else {
                break
            }
        }
        
        // Return the position of the corresponding call in original text
        return if (callIndex < matches.size) {
            matches[callIndex].range.first
        } else {
            -1
        }
    }

    /**
     * Fallback analysis using simpler pattern matching
     */
    private fun fallbackConfigAnalysis(file: PsiFile, holder: ProblemsHolder) {
        val codeText = file.text
        
        // Simple pattern to detect potential configuration inconsistencies
        val getRdbStorePattern = Regex("""getRdbStore\s*\([^)]+\)""")
        val matches = getRdbStorePattern.findAll(codeText).toList()
        
        if (matches.size > 1) {
            // If multiple getRdbStore calls found, suggest checking consistency
            matches.forEach { match ->
                val textRange = TextRange(match.range.first, match.range.last + 1)
                if (textRange.startOffset >= 0 && textRange.endOffset <= file.textLength && 
                    textRange.startOffset < textRange.endOffset) {
                    
                    createProblemDescriptor(
                        file,
                        "Multiple getRdbStore calls detected. " +
                        "Ensure that all calls for the same database name use consistent configuration parameters " +
                        "(securityLevel, encrypt, isReadOnly, customDir).",
                        holder,
                        textRange
                    )
                }
            }
        }
    }

    /**
     * Data class representing a getRdbStore call
     */
    private data class RdbStoreCall(
        val configParameter: String,
        val configuration: DatabaseConfiguration?,
        val startOffset: Int,
        val endOffset: Int,
        val fullMatch: String
    )

    /**
     * Data class representing database configuration
     */
    private data class DatabaseConfiguration(
        var name: String? = null,
        var securityLevel: String? = null,
        var encrypt: String? = null,
        var isReadOnly: String? = null,
        var customDir: String? = null,
        // Store all parameters including unknown ones
        val allParameters: MutableMap<String, String> = mutableMapOf()
    )

    /**
     * Data class representing a configuration violation
     */
    private data class ConfigurationViolation(
        val databaseName: String,
        val inconsistentCall: RdbStoreCall,
        val referenceCall: RdbStoreCall,
        val inconsistentParameters: List<String>,
        val reason: String
    )
}