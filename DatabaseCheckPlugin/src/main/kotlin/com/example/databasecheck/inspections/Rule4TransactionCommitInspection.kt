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
 * Rule 4: Transaction Commit and Rollback Detection
 *
 * This inspection detects violations of HarmonyOS Database Robustness Rule 4, which ensures
 * that transactions have proper commit and rollback handling.
 *
 * ## Rule Requirements:
 * 1. Every transaction creation must have a corresponding commit operation
 * 2. Exception handling must include rollback operations for transaction cleanup
 * 3. Transactions should not be left open without proper closure
 *
 * ## Detection Methods:
 * ### Method 1: Missing Commit Detection
 * - Track transaction variables from createTransaction calls
 * - Verify each transaction has a corresponding commit call
 *
 * ### Method 2: Missing Rollback Detection
 * - Analyze try-catch blocks containing transactions
 * - Ensure catch blocks include rollback operations for transaction cleanup
 *
 * ## Violation Types:
 * - **Missing Commit**: Transaction created without corresponding commit
 * - **Missing Rollback**: Exception handling without transaction rollback
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule4TransactionCommitInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "Transaction Commit and Rollback"
    override fun getRuleNumber(): Int = 4
    override fun getDescription(): String =
        "Ensures transactions have proper commit operations and exception handling includes rollback operations."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }

    /**
     * Analyze JavaScript file for Rule4 violations.
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        try {
            // Step 0: Remove comments to avoid parsing interference
            val originalText = file.text
            val codeWithoutComments = removeComments(originalText)
            
            // Step 1: Extract function calls and variable assignments with scope awareness
            val (functionCalls, variableAssignments) = JavaScriptAnalyzer.extractWithFunctionScopes(codeWithoutComments)
            
            // Step 2: Find transaction commit/rollback violations
            val transactionViolations = findTransactionCommitViolations(functionCalls, variableAssignments, codeWithoutComments)
            
            // Step 3: Report violations
            reportViolations(transactionViolations, file, holder)
            
        } catch (e: Exception) {
            // Fallback analysis if main analysis fails
            fallbackTransactionAnalysis(file, holder)
        }
    }

    /**
     * Find transaction commit and rollback violations by tracking transaction lifecycle.
     */
    private fun findTransactionCommitViolations(
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
                val transactionViolationsInScope = analyzeTransactionLifecycle(
                    transactionCall, scopeCalls, scopeAssignments, codeText
                )
                violations.addAll(transactionViolationsInScope)
            }
        }
        
        return violations
    }

    /**
     * Analyze a single transaction's lifecycle for commit/rollback violations.
     */
    private fun analyzeTransactionLifecycle(
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
            
            // Step 3: Check for missing commit
            val hasCommit = transactionOperations.any { op ->
                DatabaseConstants.TRANSACTION_COMMIT_OPERATIONS.any { commit ->
                    op.functionName.endsWith(".$commit") && commit == "commit"
                }
            }
            
            if (!hasCommit) {
                violations.add(TransactionViolation(
                    operation = createProhibitedOperation(transactionCall),
                    violationType = ViolationType.MISSING_COMMIT,
                    reason = "Transaction created without corresponding commit operation. Transactions must be explicitly committed.",
                    transactionVariable = transactionVariable
                ))
            }
            
            // Step 4: Check for missing rollback in exception handling
            val missingRollbackViolations = checkMissingRollback(
                transactionCall, transactionVariable, scopeCalls, codeText
            )
            violations.addAll(missingRollbackViolations)
        }
        
        return violations
    }

    /**
     * Check for missing rollback operations in exception handling blocks.
     * Uses a simpler approach that's more reliable than complex regex parsing.
     */
    private fun checkMissingRollback(
        transactionCall: JavaScriptAnalyzer.FunctionCall,
        transactionVariable: String,
        scopeCalls: List<JavaScriptAnalyzer.FunctionCall>,
        codeText: String
    ): List<TransactionViolation> {
        val violations = mutableListOf<TransactionViolation>()
        
        // Simplified approach: look for try-catch patterns around the transaction
        val simplifiedTryCatchCheck = checkForMissingRollbackSimple(codeText, transactionCall.startOffset, transactionVariable)
        
        if (simplifiedTryCatchCheck) {
            violations.add(TransactionViolation(
                operation = createProhibitedOperation(transactionCall),
                violationType = ViolationType.MISSING_ROLLBACK,
                reason = "Exception handling missing rollback operation for transaction '$transactionVariable'. " +
                        "Add rollback in catch block to prevent transaction leaks.",
                transactionVariable = transactionVariable
            ))
        }
        
        return violations
    }
    
    /**
     * Simplified check for missing rollback using localized try-catch analysis.
     * Instead of analyzing the entire function, look for the nearest try-catch block around the transaction.
     */
    private fun checkForMissingRollbackSimple(codeText: String, transactionOffset: Int, transactionVariable: String): Boolean {
        // Find the nearest try-catch block that contains this transaction
        val tryCatchBlock = findNearestTryCatchBlock(codeText, transactionOffset, transactionVariable)
            ?: return false
        
        // Check if the catch block contains rollback for this transaction variable
        val hasDirectRollback = tryCatchBlock.catchBlock.contains("$transactionVariable.rollback")
        val hasConditionalRollback = Regex("""if\s*\(\s*$transactionVariable\s*\)[\s\S]*?$transactionVariable\.rollback""")
            .containsMatchIn(tryCatchBlock.catchBlock)
        
        // Missing rollback if neither direct nor conditional rollback is found
        return !hasDirectRollback && !hasConditionalRollback
    }
    
    /**
     * Find the nearest try-catch block that contains the given transaction offset.
     * This method specifically looks for try-catch patterns around the transaction,
     * rather than parsing the entire function scope.
     */
    private fun findNearestTryCatchBlock(codeText: String, transactionOffset: Int, transactionVariable: String): TryCatchBlock? {
        // Look for try blocks that appear before the transaction offset
        val tryPattern = Regex("""try\s*\{""")
        val tryMatches = tryPattern.findAll(codeText).toList()
        
        for (tryMatch in tryMatches.reversed()) { // Check from nearest to farthest
            val tryStart = tryMatch.range.first
            
            if (tryStart > transactionOffset) continue // Try block starts after transaction
            
            // Find the matching opening brace for this try
            val tryOpenBrace = tryMatch.range.last
            val tryCloseBrace = findMatchingBrace(codeText, tryOpenBrace)
            
            if (tryCloseBrace == -1) continue
            
            // Check if transaction is within this try block
            if (transactionOffset > tryStart && transactionOffset < tryCloseBrace + 1) {
                // Find the corresponding catch block
                val catchPattern = Regex("""\}\s*catch\s*\([^)]*\)\s*\{""")
                val catchMatch = catchPattern.find(codeText, tryCloseBrace)
                
                if (catchMatch != null && catchMatch.range.first == tryCloseBrace) {
                    // Found the catch block right after this try block
                    val catchOpenBrace = catchMatch.range.last
                    val catchCloseBrace = findMatchingBrace(codeText, catchOpenBrace)
                    
                    if (catchCloseBrace != -1) {
                        val tryBlock = codeText.substring(tryOpenBrace + 1, tryCloseBrace)
                        val catchBlock = codeText.substring(catchOpenBrace + 1, catchCloseBrace)
                        
                        // Verify this try block contains the transaction variable
                        if (tryBlock.contains(transactionVariable)) {
                            return TryCatchBlock(
                                tryStart = tryStart,
                                tryEnd = tryCloseBrace + 1,
                                tryBlock = tryBlock,
                                catchBlock = catchBlock
                            )
                        }
                    }
                }
            }
        }
        
        return null
    }
    
    /**
     * Find the start of the function containing the given offset.
     */
    private fun findFunctionStart(codeText: String, offset: Int): Int {
        val beforeOffset = codeText.substring(0, offset)
        val functionPattern = Regex("""(async\s+)?function\s+\w+\s*\([^)]*\)\s*\{""")
        val matches = functionPattern.findAll(beforeOffset).toList()
        return matches.lastOrNull()?.range?.first ?: -1
    }
    
    /**
     * Find the end of the function starting at the given position.
     */
    private fun findFunctionEnd(codeText: String, functionStart: Int): Int {
        if (functionStart == -1) return -1
        
        val openBracePos = codeText.indexOf('{', functionStart)
        if (openBracePos == -1) return -1
        
        return findMatchingBrace(codeText, openBracePos) + 1
    }
    
    /**
     * Find the matching closing brace for an opening brace at the given position.
     * Returns the index of the matching closing brace, or -1 if not found.
     */
    private fun findMatchingBrace(text: String, openBracePos: Int): Int {
        if (openBracePos >= text.length || text[openBracePos] != '{') return -1
        
        var braceCount = 1
        var i = openBracePos + 1
        var inString = false
        var inSingleLineComment = false
        var inMultiLineComment = false
        var escapeNext = false
        
        while (i < text.length && braceCount > 0) {
            val char = text[i]
            
            // Handle escape sequences
            if (escapeNext) {
                escapeNext = false
                i++
                continue
            }
            
            // Handle comments and strings to avoid counting braces inside them
            when {
                inSingleLineComment -> {
                    if (char == '\n') {
                        inSingleLineComment = false
                    }
                }
                inMultiLineComment -> {
                    if (char == '*' && i + 1 < text.length && text[i + 1] == '/') {
                        inMultiLineComment = false
                        i++ // Skip the '/'
                    }
                }
                inString -> {
                    when (char) {
                        '\\' -> escapeNext = true
                        '"', '\'' -> {
                            // Check if this quote matches the string delimiter
                            if (i > 0) {
                                var stringStart = i - 1
                                while (stringStart >= 0 && text[stringStart] != '"' && text[stringStart] != '\'') {
                                    stringStart--
                                }
                                if (stringStart >= 0 && text[stringStart] == char) {
                                    inString = false
                                }
                            }
                        }
                    }
                }
                else -> {
                    when (char) {
                        '"', '\'' -> inString = true
                        '/' -> {
                            if (i + 1 < text.length) {
                                when (text[i + 1]) {
                                    '/' -> inSingleLineComment = true
                                    '*' -> inMultiLineComment = true
                                }
                            }
                        }
                        '{' -> braceCount++
                        '}' -> braceCount--
                    }
                }
            }
            
            i++
        }
        
        return if (braceCount == 0) i - 1 else -1
    }

    /**
     * Extract try-catch block information from code text.
     */
    private fun extractTryCatchBlocks(codeText: String, transactionOffset: Int): List<TryCatchBlock> {
        val blocks = mutableListOf<TryCatchBlock>()
        
        // Find try-catch patterns that might contain the transaction
        val tryCatchPattern = Regex(
            """try\s*\{([^{}]*(?:\{[^{}]*}[^{}]*)*)\}\s*catch\s*\([^)]*\)\s*\{([^{}]*(?:\{[^{}]*}[^{}]*)*)}""",
            setOf(RegexOption.MULTILINE, RegexOption.DOT_MATCHES_ALL)
        )
        
        tryCatchPattern.findAll(codeText).forEach { match ->
            val tryStart = match.range.first
            val tryEnd = match.range.last + 1
            val tryBlock = match.groupValues[1]
            val catchBlock = match.groupValues[2]
            
            // Check if the transaction falls within this try block
            if (transactionOffset in tryStart..tryEnd) {
                blocks.add(TryCatchBlock(
                    tryStart = tryStart,
                    tryEnd = tryEnd,
                    tryBlock = tryBlock,
                    catchBlock = catchBlock
                ))
            }
        }
        
        return blocks
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
                ViolationType.MISSING_COMMIT -> 
                    "Missing transaction commit: ${violation.reason}"
                ViolationType.MISSING_ROLLBACK -> 
                    "Missing transaction rollback: ${violation.reason}"
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
                    "Please ensure transactions have proper commit and rollback operations."
            
            reportViolation(prohibitedOp, file, holder, message)
        }
    }

    /**
     * Transaction violation types for Rule4.
     */
    enum class ViolationType {
        MISSING_COMMIT,      // Transaction without commit
        MISSING_ROLLBACK     // Exception handling without rollback
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

    /**
     * Data class representing a try-catch block structure.
     */
    data class TryCatchBlock(
        val tryStart: Int,
        val tryEnd: Int,
        val tryBlock: String,
        val catchBlock: String
    )
}