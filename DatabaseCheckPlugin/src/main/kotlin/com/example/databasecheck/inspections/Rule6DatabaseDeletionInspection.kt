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
import com.example.databasecheck.utils.JavaScriptAnalyzer
import com.intellij.codeInspection.*
import com.intellij.psi.PsiFile

/**
 * Rule 6: Database Deletion with Handle Closure Detection
 *
 * This inspection detects violations of HarmonyOS Database Robustness Rule 6.
 * 
 * ## Simplified Rule Requirements:
 * Before calling deleteRdbStore, ensure rdbStore.close() is called.
 *
 * ## Detection Method:
 * - Find all deleteRdbStore calls in the code
 * - Check if there's a corresponding close() call before each deletion
 * - Simple temporal analysis: close must appear before delete in the code
 *
 * ## Violation Type:
 * - **Missing rdbStore.close()**: deleteRdbStore called without closing database handle
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule6DatabaseDeletionInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "Database Deletion with Handle Closure"
    override fun getRuleNumber(): Int = 6
    override fun getDescription(): String =
        "Ensures rdbStore.close() is called before deleteRdbStore()."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }

    /**
     * Analyze JavaScript file for Rule6 violations.
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        try {
            val originalText = file.text
            val codeWithoutComments = removeComments(originalText)
            
            // Step 1: Extract function calls and variable assignments with scope awareness
            val (functionCalls, variableAssignments) = JavaScriptAnalyzer.extractWithFunctionScopes(codeWithoutComments)
            
            // Step 2: Find database deletion violations
            val deletionViolations = findDatabaseDeletionViolations(functionCalls, variableAssignments, codeWithoutComments)
            
            // Step 3: Report violations
            reportViolations(deletionViolations, file, holder)
            
        } catch (@Suppress("UNUSED_PARAMETER") e: Exception) {
            // Fallback analysis if main analysis fails
            fallbackDeletionAnalysis(file, holder)
        }
    }

    /**
     * Find database deletion violations.
     * Simple rule: check if deleteRdbStore is called without rdbStore.close() before it.
     */
    private fun findDatabaseDeletionViolations(
        calls: List<JavaScriptAnalyzer.FunctionCall>,
        @Suppress("UNUSED_PARAMETER") variableAssignments: List<JavaScriptAnalyzer.VariableAssignment>,
        codeText: String
    ): List<DatabaseDeletionViolation> {
        val violations = mutableListOf<DatabaseDeletionViolation>()
        
        // Find all deleteRdbStore calls
        val deleteRdbStoreCalls = calls.filter { call ->
            call.functionName.contains("deleteRdbStore") ||
            call.functionName.endsWith(".deleteRdbStore")
        }
        
        // For each deleteRdbStore call, check if rdbStore.close() is called before it
        for (deleteCall in deleteRdbStoreCalls) {
            if (!isRdbStoreClosedBeforeDeletion(deleteCall, codeText)) {
                violations.add(DatabaseDeletionViolation(
                    operation = createProhibitedOperation(deleteCall),
                    violationType = DeletionViolationType.MISSING_RDBSTORE_CLOSE,
                    reason = "deleteRdbStore called without rdbStore.close(). " +
                            "Database handle must be closed before deletion.",
                    functionScope = deleteCall.functionScope
                ))
            }
        }
        
        return violations
    }

    /**
     * Check if rdbStore.close() is called before deleteRdbStore.
     * Simple pattern matching for any rdbStore close operation.
     */
    private fun isRdbStoreClosedBeforeDeletion(
        deleteCall: JavaScriptAnalyzer.FunctionCall,
        codeText: String
    ): Boolean {
        val beforeDeletion = codeText.substring(0, deleteCall.startOffset)
        
        // Look for any rdbStore close patterns before the deletion
        val closePatterns = listOf(
            Regex("""rdbStore\s*\??\.\s*close\s*\(\s*\)"""),
            Regex("""\w+\s*\??\.\s*close\s*\(\s*\)""")
        )
        
        return closePatterns.any { pattern ->
            pattern.containsMatchIn(beforeDeletion)
        }
    }

    /**
     * Convert JavaScriptAnalyzer.FunctionCall to ProhibitedOperation.
     */
    private fun createProhibitedOperation(call: JavaScriptAnalyzer.FunctionCall): ProhibitedOperation {
        return ProhibitedOperation(
            operationName = call.functionName,
            startPos = call.startOffset,
            endPos = call.endOffset,
            fullMatch = "${call.functionName}(${call.arguments.joinToString(", ")})",
            parameters = call.arguments.joinToString(", "),
            objectName = call.objectName
        )
    }

    /**
     * Report all detected violations.
     */
    private fun reportViolations(violations: List<DatabaseDeletionViolation>, file: PsiFile, holder: ProblemsHolder) {
        for (violation in violations) {
            val message = when (violation.violationType) {
                DeletionViolationType.MISSING_RDBSTORE_CLOSE -> 
                    "Missing rdbStore.close(): ${violation.reason}"
                DeletionViolationType.MISSING_RESULTSET_CLOSE -> 
                    "Missing ResultSet.close(): ${violation.reason}"
                DeletionViolationType.IMPROPER_SEQUENCE -> 
                    "Improper closure sequence: ${violation.reason}"
            }
            
            reportViolation(violation.operation, file, holder, message)
        }
    }

    /**
     * Fallback analysis for database deletion if main analysis fails.
     */
    private fun fallbackDeletionAnalysis(file: PsiFile, holder: ProblemsHolder) {
        val originalText = file.text
        val codeWithoutComments = removeComments(originalText)
        
        // Simple pattern matching for deleteRdbStore without rdbStore.close()
        val deleteRdbStorePattern = Regex(
            """deleteRdbStore\s*\([^)]*\)""",
            RegexOption.MULTILINE
        )
        
        deleteRdbStorePattern.findAll(codeWithoutComments).forEach { match ->
            val startPos = match.range.first
            val endPos = match.range.last + 1
            
            // Check if there's rdbStore.close() in the surrounding context
            val contextBefore = codeWithoutComments.substring(0, startPos)
            val hasRdbStoreClose = contextBefore.contains("rdbStore.close()") ||
                                  contextBefore.contains("rdbStore?.close()")
            
            if (!hasRdbStoreClose) {
                val prohibitedOp = ProhibitedOperation(
                    operationName = match.value,
                    startPos = startPos,
                    endPos = endPos,
                    fullMatch = match.value,
                    parameters = ""
                )
                
                val message = "Database deletion without proper handle closure (fallback analysis). " +
                        "Ensure rdbStore.close() is called before deleteRdbStore()."
                
                reportViolation(prohibitedOp, file, holder, message)
            }
        }
    }

    /**
     * Database deletion violation types for Rule6.
     */
    enum class DeletionViolationType {
        MISSING_RDBSTORE_CLOSE,     // deleteRdbStore without rdbStore.close()
        MISSING_RESULTSET_CLOSE,    // ResultSet not closed before deletion
        IMPROPER_SEQUENCE           // Wrong order of closure operations
    }

    /**
     * Database deletion violation with enhanced type information.
     */
    data class DatabaseDeletionViolation(
        val operation: ProhibitedOperation,
        val violationType: DeletionViolationType,
        val reason: String,
        val functionScope: String? = null,
        val resultSetVariable: String? = null
    )


}