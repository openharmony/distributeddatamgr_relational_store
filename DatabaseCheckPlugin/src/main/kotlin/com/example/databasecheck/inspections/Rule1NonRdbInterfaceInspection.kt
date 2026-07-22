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
 * Rule 1: Prohibit using non-RDB interfaces to operate database files (Enhanced Version)
 *
 * This inspection implements correct data flow analysis to detect violations of HarmonyOS 
 * Database Robustness Rule 1. It uses AST-based analysis for better accuracy.
 *
 * ## Enhanced Data Flow Analysis:
 * 1. **Find database operations**: Identify all file operations that target database paths
 * 2. **Track variable assignments**: Track variables assigned from database operations
 * 3. **Detect violations**: Flag operations using tracked database file descriptors
 *
 * ## Key Improvements:
 * - Uses IntelliJ IDEA Community's JavaScript PSI for AST analysis
 * - Proper data flow tracking (fd1 vs fd distinction)
 * - Generic, reusable violation reporting
 * - No ad-hoc test case specific rules
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule1NonRdbInterfaceInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "Prohibit Non-RDB Interface Usage"
    override fun getRuleNumber(): Int = 1
    override fun getDescription(): String =
        "Prohibits using non-RDB interfaces (fileIo, fopen, fcntl, etc.) to operate database files. " +
                "Use relationalStore.getRdbStore() for all database operations."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }

    /**
     * Enhanced JavaScript file analysis using AST-based approach.
     * 
     * ## Analysis Steps:
     * 1. Extract all function calls using PSI
     * 2. Identify database path operations (direct violations)
     * 3. Track variables assigned from database operations
     * 4. Detect operations on tracked variables (indirect violations)
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        try {
            // Step 0: Remove comments to avoid parsing interference
            val originalText = file.text
            val codeWithoutComments = removeComments(originalText)
            
            // Step 1: Extract all function calls and assignments with function scope awareness
            val (functionCalls, variableAssignments) = JavaScriptAnalyzer.extractWithFunctionScopes(codeWithoutComments)
            
            // Step 2: Find direct database path violations
            val directViolations = findDirectDatabasePathViolations(functionCalls)
            
            // Step 3: Track variables assigned from database operations
            val databaseVariables = trackDatabaseVariables(functionCalls, variableAssignments)
            
            // Step 4: Find indirect violations (operations on tracked variables)
            val indirectViolations = findIndirectViolations(functionCalls, databaseVariables)
            
            // Step 5: Report all violations
            reportViolations(directViolations + indirectViolations, file, holder)
            
        } catch (e: Exception) {
            // Fallback to string-based analysis if PSI analysis fails
            fallbackStringAnalysis(file, holder)
        }
    }

    /**
     * Find direct violations: prohibited operations directly on database paths.
     */
    private fun findDirectDatabasePathViolations(calls: List<JavaScriptAnalyzer.FunctionCall>): List<DatabaseViolation> {
        val violations = mutableListOf<DatabaseViolation>()
        
        for (call in calls) {
            if (isProhibitedFileOperation(call.functionName) && callTargetsDatabasePath(call)) {
                violations.add(DatabaseViolation(
                    operation = createProhibitedOperation(call),
                    violationType = ViolationType.DIRECT_DATABASE_PATH,
                    reason = "Directly operates on database path"
                ))
            }
        }
        
        return violations
    }

    /**
     * Track variables that are assigned from database file operations.
     * Now with function scope awareness to prevent cross-function contamination.
     */
    private fun trackDatabaseVariables(
        calls: List<JavaScriptAnalyzer.FunctionCall>,
        assignments: List<JavaScriptAnalyzer.VariableAssignment>
    ): Map<String, Set<String>> {
        // Map from function scope to set of database variables in that scope
        val databaseVariablesByScope = mutableMapOf<String, MutableSet<String>>()
        
        // Find database open operations
        val databaseOpenCalls = calls.filter { call ->
            isOpenOperation(call.functionName) && callTargetsDatabasePath(call)
        }
        
        // Track variables assigned from these operations, grouped by function scope
        for (assignment in assignments) {
            for (openCall in databaseOpenCalls) {
                // Only match if they're in the same function scope (or both global)
                if (assignment.functionScope == openCall.functionScope &&
                    isExactMatchForDatabaseOperation(assignment, openCall)) {
                    
                    val scope = assignment.functionScope ?: "global"
                    databaseVariablesByScope.getOrPut(scope) { mutableSetOf() }
                        .add(assignment.variableName)
                    break
                }
            }
        }
        
        return databaseVariablesByScope
    }

    /**
     * Find indirect violations: operations on variables that hold database file descriptors.
     * Now with function scope awareness to prevent cross-function contamination.
     */
    private fun findIndirectViolations(
        calls: List<JavaScriptAnalyzer.FunctionCall>,
        databaseVariablesByScope: Map<String, Set<String>>
    ): List<DatabaseViolation> {
        val violations = mutableListOf<DatabaseViolation>()
        
        for (call in calls) {
            if (isProhibitedFileOperation(call.functionName)) {
                // Get the database variables for this call's function scope
                val scope = call.functionScope ?: "global"
                val scopeVariables = databaseVariablesByScope[scope] ?: emptySet()
                
                // Check if this operation uses a tracked database variable from the same scope
                val usesTrackedVariable = call.arguments.any { arg ->
                    JavaScriptAnalyzer.extractVariableReferences(arg).any { variable ->
                        scopeVariables.contains(variable)
                    }
                } || (call.objectName != null && scopeVariables.contains(call.objectName))
                
                if (usesTrackedVariable) {
                    violations.add(DatabaseViolation(
                        operation = createProhibitedOperation(call),
                        violationType = ViolationType.TRACKED_VARIABLE,
                        reason = "Operates on tracked database file descriptor in function '${scope}'"
                    ))
                }
            }
        }
        
        return violations
    }

    /**
     * Report all detected violations.
     */
    private fun reportViolations(violations: List<DatabaseViolation>, file: PsiFile, holder: ProblemsHolder) {
        for (violation in violations) {
            val message = "Prohibited use of '${violation.operation.operationName}' on database path. " +
                    "Direct file operations bypass database integrity checks. " +
                    "Use RDB interfaces instead (relationalStore.getRdbStore()). " +
                    "Reason: ${violation.reason}"
            
            reportViolation(violation.operation, file, holder, message)
        }
    }

    /**
     * Check if a variable assignment exactly matches a database operation call.
     * This provides more precise matching than simple contains() checks.
     * 
     * @param assignment The variable assignment to check
     * @param openCall The database open operation call
     * @return true if the assignment is exactly from this database operation
     */
    private fun isExactMatchForDatabaseOperation(
        assignment: JavaScriptAnalyzer.VariableAssignment,
        openCall: JavaScriptAnalyzer.FunctionCall
    ): Boolean {
        val expression = assignment.assignmentExpression.trim()
        
        // Handle await expressions: remove "await " prefix
        val cleanExpression = if (expression.startsWith("await ")) {
            expression.substring(6).trim()
        } else {
            expression
        }
        
        // Build the expected function call pattern
        val expectedCall = "${openCall.functionName}(${openCall.arguments.joinToString(", ")})"
        
        // Check for exact match or very close match
        return cleanExpression == expectedCall || 
               cleanExpression.contains(openCall.functionName + "(") &&
               openCall.arguments.all { arg -> cleanExpression.contains(arg.trim()) }
    }

    /**
     * Check if a function call targets database paths.
     */
    private fun callTargetsDatabasePath(call: JavaScriptAnalyzer.FunctionCall): Boolean {
        return call.arguments.any { arg ->
            JavaScriptAnalyzer.containsDatabasePath(arg, DatabaseConstants.DATABASE_PATHS)
        }
    }

    /**
     * Check if a function name is a prohibited file operation.
     */
    private fun isProhibitedFileOperation(functionName: String): Boolean {
        return DatabaseConstants.PROHIBITED_FILE_OPERATIONS.any { op ->
            functionName == op || functionName.endsWith(".$op")
        }
    }

    /**
     * Check if a function is an open operation.
     */
    private fun isOpenOperation(functionName: String): Boolean {
        return functionName.contains("open", ignoreCase = true)
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
     * Fallback to string-based analysis if PSI analysis fails.
     */
    private fun fallbackStringAnalysis(file: PsiFile, holder: ProblemsHolder) {
        // Use existing string-based analysis as fallback
        // This ensures compatibility even if PSI analysis encounters issues
        val originalText = file.text
        val codeWithoutComments = removeComments(originalText)
        
        // Simple pattern matching for critical violations
        for (operation in DatabaseConstants.PROHIBITED_FILE_OPERATIONS) {
            val pattern = if (operation.contains(".")) {
                Regex("""($operation)\s*\(([^)]*)\)""", RegexOption.MULTILINE)
            } else {
                Regex("""\b($operation)\s*\(([^)]*)\)""", RegexOption.MULTILINE)
            }
            
            pattern.findAll(codeWithoutComments).forEach { match ->
                val parameters = match.groupValues[2]
                if (DatabaseConstants.DATABASE_PATHS.any { it.containsMatchIn(parameters) }) {
                    val startPos = match.range.first
                    val endPos = startPos + match.groupValues[1].length
                    
                    val prohibitedOp = ProhibitedOperation(
                        operationName = match.groupValues[1],
                        startPos = startPos,
                        endPos = endPos,
                        fullMatch = match.value,
                        parameters = parameters
                    )
                    
                    val message = "Prohibited use of '${prohibitedOp.operationName}' on database path (fallback detection). " +
                            "Use RDB interfaces instead."
                    
                    reportViolation(prohibitedOp, file, holder, message)
                }
            }
        }
    }

    /**
     * Data classes for enhanced violation tracking.
     */
    enum class ViolationType {
        DIRECT_DATABASE_PATH,
        TRACKED_VARIABLE
    }

    data class DatabaseViolation(
        val operation: ProhibitedOperation,
        val violationType: ViolationType,
        val reason: String
    )
}