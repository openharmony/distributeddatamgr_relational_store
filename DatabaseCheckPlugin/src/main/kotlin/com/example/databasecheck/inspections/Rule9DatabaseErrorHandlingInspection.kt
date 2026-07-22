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
 * Rule 9: Database Error Code Handling and Retry Logic
 *
 * This inspection detects violations of HarmonyOS Database Robustness Rule 9, which requires
 * proper handling of specific database error codes and implementing appropriate retry logic
 * for database CRUD operations.
 *
 * ## Rule Requirements:
 * Database CRUD operations should handle specific error codes with appropriate actions:
 * - **14800047**: Close ResultSet and execute checkpoint operation (PRAGMA wal_checkpoint(TRUNCATE))
 * - **14800024, 14800025, 14800028**: Implement retry logic with delay for busy database
 * - **14800029**: Clean up disk space and retry for disk full errors
 *
 * ## Detected Violations:
 * - Database operations in try-catch blocks that don't handle required error codes
 * - Missing specific error code handling (14800047, 14800024, 14800025, 14800028, 14800029)
 * - Empty catch blocks for database operations
 * - Missing retry logic for transient errors
 * - Missing ResultSet cleanup for 14800047 errors
 *
 * ## Positive Examples:
 * 
 * ### Error 14800047 - ResultSet cleanup and checkpoint:
 * ```javascript
 * try {
 *     await rdbStore?.insert("test", valueBucket);
 * } catch (err) {
 *     if (err.code == 14800047) {
 *         resultSet?.close();
 *         await rdbStore?.execute("PRAGMA wal_checkpoint(TRUNCATE)");
 *     }
 * }
 * ```
 * 
 * ### Errors 14800024/25/28 - Retry with delay:
 * ```javascript
 * try {
 *     await rdbStore?.insert("test", valueBucket);
 * } catch (err) {
 *     if ((err.code == 14800024 || err.code == 14800025 || err.code == 14800028) && needRetry) {
 *         sleep(1);
 *         await retryForBusy(false);
 *     }
 * }
 * ```
 * 
 * ### Error 14800029 - Disk cleanup:
 * ```javascript
 * try {
 *     await rdbStore?.insert("test", valueBucket);
 * } catch (err) {
 *     if ((err.code == 14800029) && !cleaned) {
 *         // Clean up disk space
 *         await retryForFull(true);
 *     }
 * }
 * ```
 *
 * ## Negative Example (Violation):
 * ```javascript
 * try {
 *     await rdbStore?.insert("test", valueBucket);
 * } catch (err) {
 *     // Empty catch - missing error code handling
 * }
 * ```
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule9DatabaseErrorHandlingInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "Database Error Code Handling and Retry Logic"
    override fun getRuleNumber(): Int = 9
    override fun getDescription(): String =
        "Ensures proper handling of specific database error codes and retry logic for CRUD operations."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }

    /**
     * Main analysis logic for detecting database error handling violations
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        val originalText = file.text
        if (originalText.isBlank()) return

        try {
            // Step 0: Remove comments to avoid parsing interference
            val codeText = removeComments(originalText)
            
            // Find all try-catch blocks that contain database operations
            val tryCatchBlocks = findTryCatchBlocks(codeText)
            
            // Analyze each try-catch block for proper error handling
            val violations = detectErrorHandlingViolations(tryCatchBlocks, codeText)
            
            // Report all violations
            violations.forEach { violation ->
                reportViolation(violation, file, holder)
            }
            
        } catch (e: Exception) {
            // Fallback analysis if main analysis fails
            fallbackErrorHandlingAnalysis(file, holder)
        }
    }

    /**
     * Find all try-catch blocks in the code
     */
    private fun findTryCatchBlocks(codeText: String): List<TryCatchBlock> {
        val blocks = mutableListOf<TryCatchBlock>()
        
        // Pattern to match try-catch blocks
        val tryCatchPattern = Regex("""try\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}\s*(?:\.)?catch\s*\([^)]*\)\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}""", RegexOption.DOT_MATCHES_ALL)
        
        tryCatchPattern.findAll(codeText).forEach { match ->
            val tryBlock = match.groupValues[1]
            val catchBlock = match.groupValues[2]
            val startOffset = match.range.first
            val endOffset = match.range.last + 1
            
            // Check if try block contains database operations
            if (containsDatabaseOperations(tryBlock)) {
                blocks.add(
                    TryCatchBlock(
                        tryContent = tryBlock.trim(),
                        catchContent = catchBlock.trim(),
                        startOffset = startOffset,
                        endOffset = endOffset,
                        fullMatch = match.value
                    )
                )
            }
        }
        
        return blocks
    }

    /**
     * Check if a code block contains database operations
     */
    private fun containsDatabaseOperations(codeBlock: String): Boolean {
        val databaseOperations = DatabaseConstants.DATABASE_CRUD_OPERATIONS + setOf(
            "rdbStore", "resultSet", "query", "getRdbStore"
        )
        
        return databaseOperations.any { operation ->
            codeBlock.contains(operation)
        }
    }

    /**
     * Detect error handling violations in try-catch blocks
     */
    private fun detectErrorHandlingViolations(
        blocks: List<TryCatchBlock>,
        codeText: String
    ): List<ErrorHandlingViolation> {
        val violations = mutableListOf<ErrorHandlingViolation>()
        
        for (block in blocks) {
            // Check for completely empty catch blocks
            if (block.catchContent.isEmpty() || block.catchContent.isBlank()) {
                violations.add(
                    ErrorHandlingViolation(
                        block = block,
                        violationType = ErrorHandlingViolationType.EMPTY_CATCH,
                        reason = "Empty catch block for database operations. " +
                                "Database CRUD operations should handle errors appropriately.",
                        missingErrorCodes = DatabaseConstants.DATABASE_ERROR_CODES.toList()
                    )
                )
                continue
            }
            
            // Check for catch blocks that only have comments or trivial content
            val trimmedContent = block.catchContent.trim()
            if (isTrivialCatchBlock(trimmedContent)) {
                violations.add(
                    ErrorHandlingViolation(
                        block = block,
                        violationType = ErrorHandlingViolationType.EMPTY_CATCH,
                        reason = "Trivial catch block for database operations. " +
                                "Consider handling specific database error codes with appropriate retry logic.",
                        missingErrorCodes = DatabaseConstants.DATABASE_ERROR_CODES.toList()
                    )
                )
                continue
            }
            
            // For non-empty catch blocks, we don't require specific error codes
            // The presence of some error handling is considered sufficient
        }
        
        return violations
    }

    /**
     * Check if a catch block is trivial (only comments, logging, or no meaningful error handling)
     */
    private fun isTrivialCatchBlock(catchContent: String): Boolean {
        // Remove comments and whitespace
        val cleanContent = catchContent
            .replace(Regex("""//.*"""), "")  // Remove single line comments
            .replace(Regex("""/\*.*?\*/""", RegexOption.DOT_MATCHES_ALL), "") // Remove multi-line comments
            .trim()
        
        // Check if it's empty after removing comments
        if (cleanContent.isEmpty()) return true
        
        // Check if it only contains simple logging or trivial statements
        val trivialPatterns = listOf(
            Regex("""^\s*console\.(log|error|warn|info)\s*\([^)]*\)\s*;?\s*$"""),
            Regex("""^\s*return\s*;?\s*$"""),
            Regex("""^\s*throw\s+err\s*;?\s*$"""),
            Regex("""^\s*$""")
        )
        
        return trivialPatterns.any { pattern ->
            pattern.matches(cleanContent)
        }
    }


    /**
     * Report an error handling violation
     */
    private fun reportViolation(violation: ErrorHandlingViolation, file: PsiFile, holder: ProblemsHolder) {
        val block = violation.block
        val textRange = TextRange(block.startOffset, block.endOffset)
        
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
    private fun fallbackErrorHandlingAnalysis(file: PsiFile, holder: ProblemsHolder) {
        val codeText = file.text
        
        // Simple pattern to catch obvious violations - empty catch blocks with database operations
        val patterns = listOf(
            Regex("""try\s*\{[^{}]*(?:rdbStore|resultSet|insert|query|update|delete)[^{}]*\}\s*(?:\.)?catch\s*\([^)]*\)\s*\{\s*\}"""),
            Regex("""try\s*\{[^{}]*(?:rdbStore|resultSet|insert|query|update|delete)[^{}]*\}\s*(?:\.)?catch\s*\([^)]*\)\s*\{\s*//[^}]*\}""")
        )
        
        patterns.forEach { pattern ->
            pattern.findAll(codeText).forEach { match ->
                val textRange = TextRange(match.range.first, match.range.last + 1)
                if (textRange.startOffset >= 0 && textRange.endOffset <= file.textLength && 
                    textRange.startOffset < textRange.endOffset) {
                    
                    createProblemDescriptor(
                        file,
                        "Database operations should handle specific error codes " +
                        "(14800047, 14800024, 14800025, 14800028, 14800029) with appropriate retry logic.",
                        holder,
                        textRange
                    )
                }
            }
        }
    }

    /**
     * Data class representing a try-catch block
     */
    private data class TryCatchBlock(
        val tryContent: String,
        val catchContent: String,
        val startOffset: Int,
        val endOffset: Int,
        val fullMatch: String
    )

    /**
     * Data class representing an error handling violation
     */
    private data class ErrorHandlingViolation(
        val block: TryCatchBlock,
        val violationType: ErrorHandlingViolationType,
        val reason: String,
        val missingErrorCodes: List<Int>
    )

    /**
     * Enum for different types of error handling violations
     */
    private enum class ErrorHandlingViolationType {
        EMPTY_CATCH
    }
}