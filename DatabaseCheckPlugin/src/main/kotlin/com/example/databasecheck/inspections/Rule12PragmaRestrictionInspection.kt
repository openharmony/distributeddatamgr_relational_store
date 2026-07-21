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
 * Rule 12: SQLite Pragma Restriction
 *
 * This inspection detects violations of HarmonyOS Database Robustness Rule 12, which prohibits
 * modifying certain SQLite pragma settings that could compromise database integrity, 
 * performance, or security.
 *
 * ## Rule Requirements:
 * Prohibit the following SQLite pragma operations:
 * 1. `PRAGMA journal_mode = OFF` - Disables journaling, risking data corruption
 * 2. `PRAGMA schema_version = xxxx` - Manual schema version manipulation
 * 3. `PRAGMA synchronous = OFF` - Disables synchronization, risking data loss
 * 4. `PRAGMA journal_mode = MEMORY` - Memory-only journaling, not crash-safe
 * 5. `PRAGMA writable_schema = ON` - Allows dangerous schema modifications
 *
 * ## Detected Violations:
 * - Direct SQL execution with prohibited PRAGMA statements
 * - Database execute/executeSql calls containing forbidden pragma operations
 * - String literals or variables containing dangerous pragma settings
 * - Configuration objects with journal mode settings
 *
 * ## Positive Example (Safe):
 * ```javascript
 * async function CreateRdbStore(context) {
 *     const config = {
 *         "name": STORE_NAME,
 *         securityLevel: relationalStore.SecurityLevel.S3,
 *     }
 *     var rdbStore = undefined;
 *     try {
 *         rdbStore = await relationalStore.getRdbStore(context, config);
 *     } catch (err) {
 *         console.log(`failed, err: ${JSON.stringify(err)}`)
 *     }
 *     return rdbStore
 * }
 * ```
 *
 * ## Negative Examples (Violations):
 * ```javascript
 * // Violation - Direct pragma execution
 * await rdbStore?.execute('PRAGMA journal_mode = OFF');
 * await rdbStore?.execute('PRAGMA synchronous = OFF');
 * await rdbStore?.execute('PRAGMA writable_schema = ON');
 * 
 * // Violation - Configuration with journal mode
 * config.SetJournalMode(NativeRdb::JournalMode::MODE_OFF);
 * ```
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule12PragmaRestrictionInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "SQLite Pragma Restriction"
    override fun getRuleNumber(): Int = 12
    override fun getDescription(): String =
        "Prohibits dangerous SQLite pragma operations that could compromise database integrity."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }

    /**
     * Main analysis logic for detecting prohibited pragma operations
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        val originalText = file.text
        if (originalText.isBlank()) return

        try {
            // Step 0: Remove comments to avoid parsing interference
            val codeText = removeComments(originalText)
            
            // Find all prohibited pragma operations
            val pragmaViolations = findProhibitedPragmaOperations(codeText)
            
            // Report all violations
            pragmaViolations.forEach { violation ->
                reportViolation(violation, file, holder)
            }
            
        } catch (e: Exception) {
            // Fallback analysis if main analysis fails
            fallbackPragmaAnalysis(file, holder)
        }
    }

    /**
     * Find all prohibited pragma operations in the code
     */
    private fun findProhibitedPragmaOperations(codeText: String): List<PragmaViolation> {
        val violations = mutableListOf<PragmaViolation>()
        
        // Method 1: Direct PRAGMA statements in execute/executeSql calls
        violations.addAll(findDirectPragmaStatements(codeText))
        
        // Method 2: Configuration object method calls
        violations.addAll(findConfigurationViolations(codeText))
        
        // Method 3: String variables containing pragma statements
        violations.addAll(findPragmaInVariables(codeText))
        
        return violations
    }

    /**
     * Find direct PRAGMA statements in execute/executeSql calls
     */
    private fun findDirectPragmaStatements(codeText: String): List<PragmaViolation> {
        val violations = mutableListOf<PragmaViolation>()
        
        // Pattern to match execute/executeSql calls with PRAGMA statements
        val executePatterns = listOf(
            Regex("""(?:rdbStore\??\.|\.)?(?:execute|executeSql)\s*\(\s*['"`]([^'"`]*PRAGMA[^'"`]*?)['"`]\s*\)""", RegexOption.IGNORE_CASE),
            Regex("""(?:rdbStore\??\.|\.)?(?:execute|executeSql)\s*\(\s*([^)]*PRAGMA[^)]*?)\s*\)""", RegexOption.IGNORE_CASE)
        )
        
        for (pattern in executePatterns) {
            pattern.findAll(codeText).forEach { match ->
                val sqlStatement = match.groupValues[1].trim()
                val prohibitedPragma = findMatchingProhibitedPragma(sqlStatement)
                
                if (prohibitedPragma != null) {
                    violations.add(
                        PragmaViolation(
                            pragmaStatement = prohibitedPragma,
                            foundStatement = sqlStatement,
                            startOffset = match.range.first,
                            endOffset = match.range.last + 1,
                            violationType = PragmaViolationType.DIRECT_PRAGMA_EXECUTION,
                            reason = "Prohibited PRAGMA operation '$prohibitedPragma' detected. " +
                                    "This pragma setting can compromise database integrity, performance, or security."
                        )
                    )
                }
            }
        }
        
        return violations
    }

    /**
     * Find configuration object violations (e.g., SetJournalMode)
     */
    private fun findConfigurationViolations(codeText: String): List<PragmaViolation> {
        val violations = mutableListOf<PragmaViolation>()
        
        // Pattern to match configuration method calls
        val configPatterns = listOf(
            Regex("""\.SetJournalMode\s*\(\s*[^)]*MODE_OFF[^)]*\)""", RegexOption.IGNORE_CASE),
            Regex("""\.SetJournalMode\s*\(\s*[^)]*MEMORY[^)]*\)""", RegexOption.IGNORE_CASE),
            Regex("""journalMode\s*:\s*['"`]?(?:OFF|MEMORY)['"`]?""", RegexOption.IGNORE_CASE)
        )
        
        for (pattern in configPatterns) {
            pattern.findAll(codeText).forEach { match ->
                violations.add(
                    PragmaViolation(
                        pragmaStatement = "journal_mode configuration",
                        foundStatement = match.value,
                        startOffset = match.range.first,
                        endOffset = match.range.last + 1,
                        violationType = PragmaViolationType.CONFIG_VIOLATION,
                        reason = "Prohibited journal mode configuration detected. " +
                                "Setting journal mode to OFF or MEMORY can compromise database safety."
                    )
                )
            }
        }
        
        return violations
    }

    /**
     * Find pragma statements in string variables
     */
    private fun findPragmaInVariables(codeText: String): List<PragmaViolation> {
        val violations = mutableListOf<PragmaViolation>()
        
        // Pattern to match variable assignments with PRAGMA statements
        val variablePattern = Regex("""(?:let|var|const)\s+\w+\s*=\s*['"`]([^'"`]*PRAGMA[^'"`]*?)['"`]""", RegexOption.IGNORE_CASE)
        
        variablePattern.findAll(codeText).forEach { match ->
            val sqlStatement = match.groupValues[1].trim()
            val prohibitedPragma = findMatchingProhibitedPragma(sqlStatement)
            
            if (prohibitedPragma != null) {
                violations.add(
                    PragmaViolation(
                        pragmaStatement = prohibitedPragma,
                        foundStatement = sqlStatement,
                        startOffset = match.range.first,
                        endOffset = match.range.last + 1,
                        violationType = PragmaViolationType.VARIABLE_PRAGMA,
                        reason = "Prohibited PRAGMA statement '$prohibitedPragma' found in variable assignment. " +
                                "This pragma operation should not be used."
                    )
                )
            }
        }
        
        return violations
    }

    /**
     * Check if a SQL statement matches any prohibited pragma operation
     */
    private fun findMatchingProhibitedPragma(sqlStatement: String): String? {
        val normalizedStatement = sqlStatement.trim().replace(Regex("""\s+"""), " ")
        
        for (prohibitedPragma in DatabaseConstants.PROHIBITED_PRAGMA_OPERATIONS) {
            // Handle different matching patterns
            when {
                // Exact match
                normalizedStatement.contains(prohibitedPragma, ignoreCase = true) -> {
                    return prohibitedPragma
                }
                
                // Special case for schema_version (ends with =, needs value check)
                prohibitedPragma == "PRAGMA schema_version =" && 
                normalizedStatement.contains("PRAGMA schema_version", ignoreCase = true) -> {
                    return prohibitedPragma
                }
                
                // Special case for synchronous without spaces
                prohibitedPragma == "PRAGMA synchronous=OFF" && 
                normalizedStatement.contains("PRAGMA synchronous=OFF", ignoreCase = true) -> {
                    return prohibitedPragma
                }
                
                // Special case for synchronous with spaces  
                prohibitedPragma == "PRAGMA synchronous = OFF" && 
                normalizedStatement.contains("PRAGMA synchronous = OFF", ignoreCase = true) -> {
                    return prohibitedPragma
                }
            }
        }
        
        return null
    }

    /**
     * Report a pragma violation
     */
    private fun reportViolation(violation: PragmaViolation, file: PsiFile, holder: ProblemsHolder) {
        val textRange = TextRange(violation.startOffset, violation.endOffset)
        
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

    /**
     * Fallback analysis using simpler pattern matching
     */
    private fun fallbackPragmaAnalysis(file: PsiFile, holder: ProblemsHolder) {
        val codeText = file.text
        
        // Simple pattern to catch obvious PRAGMA violations
        val patterns = listOf(
            Regex("""PRAGMA\s+journal_mode\s*=\s*OFF""", RegexOption.IGNORE_CASE),
            Regex("""PRAGMA\s+synchronous\s*=?\s*OFF""", RegexOption.IGNORE_CASE),
            Regex("""PRAGMA\s+journal_mode\s*=\s*MEMORY""", RegexOption.IGNORE_CASE),
            Regex("""PRAGMA\s+writable_schema\s*=\s*ON""", RegexOption.IGNORE_CASE),
            Regex("""PRAGMA\s+schema_version\s*=""", RegexOption.IGNORE_CASE)
        )
        
        patterns.forEach { pattern ->
            pattern.findAll(codeText).forEach { match ->
                val textRange = TextRange(match.range.first, match.range.last + 1)
                if (textRange.startOffset >= 0 && textRange.endOffset <= file.textLength && 
                    textRange.startOffset < textRange.endOffset) {
                    
                    createProblemDescriptor(
                        file,
                        "Prohibited SQLite PRAGMA operation detected. " +
                        "This operation can compromise database integrity, performance, or security.",
                        holder,
                        textRange
                    )
                }
            }
        }
    }

    /**
     * Data class representing a pragma violation
     */
    private data class PragmaViolation(
        val pragmaStatement: String,
        val foundStatement: String,
        val startOffset: Int,
        val endOffset: Int,
        val violationType: PragmaViolationType,
        val reason: String
    )

    /**
     * Enum for different types of pragma violations
     */
    private enum class PragmaViolationType {
        DIRECT_PRAGMA_EXECUTION,
        CONFIG_VIOLATION,
        VARIABLE_PRAGMA
    }
}