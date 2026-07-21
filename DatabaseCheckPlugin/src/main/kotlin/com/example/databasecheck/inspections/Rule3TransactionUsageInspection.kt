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
 * Rule 3: Transaction Usage Optimization Detection
 *
 * This inspection detects violations of HarmonyOS Database Robustness Rule 3, which governs
 * proper transaction usage patterns to avoid unnecessary transactions and time-consuming operations.
 *
 * ## Rule Requirements:
 * 1. Avoid unnecessary transactions (e.g., for single operations or query-only operations)
 * 2. Keep transactions short - only atomic database CRUD operations
 * 3. Prohibit time-consuming operations in transactions (IPC, download, upload, etc.)
 *
 * ## Detection Methods:
 * ### Method 1: Single Operation Detection
 * - Detect transactions with only one CRUD operation
 * - Recommend removing transaction for single operations
 *
 * ### Method 2: Time-consuming Operation Detection
 * - Track transaction variables from createTransaction to commit/rollback
 * - Detect prohibited operations within transaction scope
 * - Allow loops if they don't contain prohibited operations
 *
 * ## Violation Types:
 * - **Unnecessary Transaction**: Single CRUD operation in transaction
 * - **Time-consuming Operation**: Prohibited operations in transaction scope
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule3TransactionUsageInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "Transaction Usage Optimization"
    override fun getRuleNumber(): Int = 3
    override fun getDescription(): String =
        "Detects unnecessary transactions and time-consuming operations in transaction scope. " +
                "Recommends keeping transactions short with only atomic database CRUD operations."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }

    /**
     * Analyze JavaScript file for Rule3 violations.
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        try {
            // Step 0: Remove comments to avoid parsing interference
            val originalText = file.text
            val codeWithoutComments = removeComments(originalText)
            
            // Step 1: Extract function calls and variable assignments with scope awareness
            val (functionCalls, variableAssignments) = JavaScriptAnalyzer.extractWithFunctionScopes(codeWithoutComments)
            
            // Step 2: Find transaction usage violations
            val transactionViolations = findTransactionViolations(functionCalls, variableAssignments, codeWithoutComments)
            
            // Step 3: Report violations
            reportViolations(transactionViolations, file, holder)
            
        } catch (e: Exception) {
            // Fallback analysis if main analysis fails
            fallbackTransactionAnalysis(file, holder)
        }
    }

    /**
     * Find transaction usage violations by tracking transaction variables.
     */
    private fun findTransactionViolations(
        calls: List<JavaScriptAnalyzer.FunctionCall>,
        variableAssignments: List<JavaScriptAnalyzer.VariableAssignment>,
        codeText: String
    ): List<TransactionViolation> {
        val violations = mutableListOf<TransactionViolation>()
        
        // Group calls by function scope for analysis
        val callsByScope = calls.groupBy { it.functionScope }
        val assignmentsByScope = variableAssignments.groupBy { it.functionScope }
        
        for ((scope, scopeCalls) in callsByScope) {
            val scopeAssignments = assignmentsByScope[scope] ?: emptyList()
            
            // Find transaction creation calls in this scope
            val transactionCreations = scopeCalls.filter { call ->
                DatabaseConstants.TRANSACTION_CREATE_OPERATIONS.any { op ->
                    call.functionName == op || call.functionName.endsWith(".$op")
                }
            }
            
            // Analyze each transaction in this scope
            for (transactionCall in transactionCreations) {
                val transactionViolationsInScope = analyzeTransactionScope(
                    transactionCall, scopeCalls, scopeAssignments, codeText
                )
                violations.addAll(transactionViolationsInScope)
            }
        }
        
        return violations
    }

    /**
     * Analyze a single transaction scope for violations.
     */
    private fun analyzeTransactionScope(
        transactionCall: JavaScriptAnalyzer.FunctionCall,
        scopeCalls: List<JavaScriptAnalyzer.FunctionCall>,
        scopeAssignments: List<JavaScriptAnalyzer.VariableAssignment>,
        codeText: String
    ): List<TransactionViolation> {
        val violations = mutableListOf<TransactionViolation>()
        
        // Step 1: Find the transaction variable assignment
        val transactionVariable = findTransactionVariable(transactionCall, scopeAssignments)
        
        if (transactionVariable != null) {
            // Step 2: Find all operations on this transaction variable
            val transactionOperations = findTransactionOperations(transactionVariable, scopeCalls)
            
            // Step 3: Check for unnecessary transaction (single operation)
            val crudOperations = transactionOperations.filter { op ->
                DatabaseConstants.DATABASE_CRUD_OPERATIONS.any { crud ->
                    op.functionName.endsWith(".$crud")
                }
            }
            
            if (crudOperations.size == 1) {
                // Check if there are loops in the transaction scope
                val hasLoopsInTransaction = hasLoopsInTransactionScope(
                    transactionCall, transactionOperations, codeText
                )
                
                // Only report unnecessary transaction if there are no loops
                if (!hasLoopsInTransaction) {
                    violations.add(TransactionViolation(
                        operation = createProhibitedOperation(crudOperations.first()),
                        violationType = ViolationType.UNNECESSARY_TRANSACTION,
                        reason = "Transaction contains only one CRUD operation. Consider removing transaction for single operations.",
                        transactionVariable = transactionVariable
                    ))
                }
            }
            
            // Step 4: Check for time-consuming operations in transaction scope
            val timeConsumingOps = findTimeConsumingOperations(
                transactionCall, transactionOperations, scopeCalls
            )
            
            for (timeConsumingOp in timeConsumingOps) {
                violations.add(TransactionViolation(
                    operation = createProhibitedOperation(timeConsumingOp),
                    violationType = ViolationType.TIME_CONSUMING_OPERATION,
                    reason = "Time-consuming operation '${timeConsumingOp.functionName}' detected in transaction scope. " +
                            "Transactions should only contain atomic database CRUD operations.",
                    transactionVariable = transactionVariable
                ))
            }
        }
        
        return violations
    }

    /**
     * Find the variable that stores the transaction object.
     */
    private fun findTransactionVariable(
        transactionCall: JavaScriptAnalyzer.FunctionCall,
        assignments: List<JavaScriptAnalyzer.VariableAssignment>
    ): String? {
        // Look for assignments that include this transaction call
        for (assignment in assignments) {
            // Check if assignment expression contains the transaction call
            if (assignment.startOffset <= transactionCall.startOffset && 
                assignment.endOffset >= transactionCall.endOffset) {
                return assignment.variableName
            }
            
            // Also check for assignments that happen around the same time
            val offsetDiff = kotlin.math.abs(assignment.startOffset - transactionCall.startOffset)
            if (offsetDiff < 100 && assignment.assignmentExpression.contains("createTransaction")) {
                return assignment.variableName
            }
        }
        
        return null
    }

    /**
     * Find all operations on the transaction variable.
     */
    private fun findTransactionOperations(
        transactionVariable: String,
        calls: List<JavaScriptAnalyzer.FunctionCall>
    ): List<JavaScriptAnalyzer.FunctionCall> {
        return calls.filter { call ->
            call.objectName == transactionVariable ||
            call.functionName.startsWith("$transactionVariable.")
        }
    }

    /**
     * Check if there are loops within the transaction scope.
     * If loops exist and contain no prohibited operations, single CRUD operations should not be flagged.
     */
    private fun hasLoopsInTransactionScope(
        transactionStart: JavaScriptAnalyzer.FunctionCall,
        transactionOps: List<JavaScriptAnalyzer.FunctionCall>,
        codeText: String
    ): Boolean {
        // Find transaction end (commit/rollback)
        val transactionEnd = transactionOps.find { op ->
            DatabaseConstants.TRANSACTION_COMMIT_OPERATIONS.any { commit ->
                op.functionName.endsWith(".$commit")
            }
        }
        
        val endOffset = transactionEnd?.startOffset ?: Int.MAX_VALUE
        
        // Get the code text within transaction scope to analyze for loops
        val codeInScope = extractCodeInRange(codeText, transactionStart.endOffset, endOffset)
        
        // Check for common loop patterns in JavaScript
        val loopPatterns = listOf(
            Regex("""for\s*\([^)]*\)\s*\{"""),        // for loops
            Regex("""while\s*\([^)]*\)\s*\{"""),      // while loops
            Regex("""do\s*\{"""),                     // do-while loops
            Regex("""\.forEach\s*\("""),              // forEach loops
            Regex("""\.map\s*\("""),                  // map operations
            Regex("""\.filter\s*\("""),               // filter operations
            Regex("""\.reduce\s*\(""")                // reduce operations
        )
        
        return loopPatterns.any { pattern -> 
            pattern.containsMatchIn(codeInScope)
        }
    }
    
    /**
     * Extract code text within a specific offset range from the full code text.
     */
    private fun extractCodeInRange(codeText: String, startOffset: Int, endOffset: Int): String {
        if (startOffset < 0 || endOffset > codeText.length || startOffset >= endOffset) {
            return ""
        }
        return codeText.substring(startOffset, kotlin.math.min(endOffset, codeText.length))
    }

    /**
     * Find time-consuming operations within transaction scope.
     */
    private fun findTimeConsumingOperations(
        transactionStart: JavaScriptAnalyzer.FunctionCall,
        transactionOps: List<JavaScriptAnalyzer.FunctionCall>,
        allCalls: List<JavaScriptAnalyzer.FunctionCall>
    ): List<JavaScriptAnalyzer.FunctionCall> {
        val timeConsumingOps = mutableListOf<JavaScriptAnalyzer.FunctionCall>()
        
        // Find transaction end (commit/rollback)
        val transactionEnd = transactionOps.find { op ->
            DatabaseConstants.TRANSACTION_COMMIT_OPERATIONS.any { commit ->
                op.functionName.endsWith(".$commit")
            }
        }
        
        val endOffset = transactionEnd?.startOffset ?: Int.MAX_VALUE
        
        // Find operations between transaction start and end
        val operationsInScope = allCalls.filter { call ->
            call.startOffset > transactionStart.endOffset && 
            call.startOffset < endOffset
        }
        
        // Check for prohibited operations (exclude transaction's own CRUD operations)
        for (operation in operationsInScope) {
            // Skip if this is a transaction CRUD operation
            val isTransactionCrud = transactionOps.any { transOp ->
                transOp.startOffset == operation.startOffset && transOp.endOffset == operation.endOffset
            }
            
            if (!isTransactionCrud) {
                val isProhibited = DatabaseConstants.PROHIBITED_TRANSACTION_OPERATIONS.any { prohibited ->
                    // Check object name (for calls like ipc.sendMessage, socket.connect, rpc.call)
                    operation.objectName?.equals(prohibited, ignoreCase = true) == true ||
                    // Check function name exactly (not contains)
                    operation.functionName.equals(prohibited, ignoreCase = true) ||
                    operation.functionName.endsWith(".$prohibited", ignoreCase = true) ||
                    // Check if function name starts with prohibited operation
                    operation.functionName.startsWith("$prohibited.", ignoreCase = true) ||
                    // Check arguments for prohibited operations
                    operation.arguments.any { arg -> 
                        prohibited in arg.lowercase()
                    }
                }
                
                if (isProhibited) {
                    timeConsumingOps.add(operation)
                }
            }
        }
        
        return timeConsumingOps
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
    private fun reportViolations(violations: List<TransactionViolation>, file: PsiFile, holder: ProblemsHolder) {
        for (violation in violations) {
            val message = when (violation.violationType) {
                ViolationType.UNNECESSARY_TRANSACTION -> 
                    "Unnecessary transaction: ${violation.reason}"
                ViolationType.TIME_CONSUMING_OPERATION -> 
                    "Time-consuming operation in transaction: ${violation.reason}"
            }
            
            reportViolation(violation.operation, file, holder, message)
        }
    }

    /**
     * Fallback analysis for transaction operations if main analysis fails.
     */
    private fun fallbackTransactionAnalysis(file: PsiFile, holder: ProblemsHolder) {
        val originalText = file.text
        val codeWithoutComments = removeComments(originalText)
        
        // Simple pattern matching for transaction operations
        val transactionPattern = Regex(
            """(rdbStore\.createTransaction|rdbStore\.beginTransaction)\s*\([^)]*\)""",
            RegexOption.MULTILINE
        )
        
        transactionPattern.findAll(codeWithoutComments).forEach { match ->
            val startPos = match.range.first
            val endPos = match.range.last + 1
            
            val prohibitedOp = ProhibitedOperation(
                operationName = match.value,
                startPos = startPos,
                endPos = endPos,
                fullMatch = match.value,
                parameters = ""
            )
            
            val message = "Transaction usage detected (fallback analysis). " +
                    "Please ensure transactions are necessary and contain only atomic CRUD operations."
            
            reportViolation(prohibitedOp, file, holder, message)
        }
    }

    /**
     * Transaction violation types for Rule3.
     */
    enum class ViolationType {
        UNNECESSARY_TRANSACTION,     // Single operation transaction
        TIME_CONSUMING_OPERATION     // Prohibited operation in transaction
    }

    /**
     * Transaction violation with enhanced type information.
     */
    data class TransactionViolation(
        val operation: ProhibitedOperation,
        val violationType: ViolationType,
        val reason: String,
        val transactionVariable: String? = null
    )
}