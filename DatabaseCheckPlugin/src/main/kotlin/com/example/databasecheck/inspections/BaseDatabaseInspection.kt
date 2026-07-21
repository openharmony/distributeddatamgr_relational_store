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

import com.intellij.codeInspection.*
import com.intellij.codeHighlighting.HighlightDisplayLevel
import com.intellij.openapi.util.TextRange
import com.intellij.psi.PsiElement
import com.intellij.psi.PsiElementVisitor
import com.intellij.psi.PsiFile

/**
 * Base class for all database robustness rule inspections
 * 
 * This class provides common functionality for database rule inspections including:
 * - JavaScript/TypeScript file detection
 * - Comment removal utilities
 * - Common data structures for prohibited operations
 * - Unified problem reporting mechanisms
 * - Utility methods for code analysis
 */
abstract class BaseDatabaseInspection : LocalInspectionTool() {
    
    abstract fun getRuleName(): String
    abstract fun getRuleNumber(): Int
    abstract fun getDescription(): String
    
    override fun getGroupDisplayName(): String = "Database Robustness Rules"
    
    override fun getDisplayName(): String = "Rule ${getRuleNumber()}: ${getRuleName()}"
    
    override fun getShortName(): String = "DatabaseRule${getRuleNumber()}"
    
    override fun isEnabledByDefault(): Boolean = true
    
    override fun getDefaultLevel(): HighlightDisplayLevel = HighlightDisplayLevel.WARNING
    
    /**
     * Creates a visitor for all files
     */
    override fun buildVisitor(holder: ProblemsHolder, isOnTheFly: Boolean): PsiElementVisitor {
        return object : PsiElementVisitor() {
            override fun visitFile(file: PsiFile) {
                if (isJavaScriptFile(file)) {
                    visitJavaScriptFile(file, holder)
                }
            }
            
            override fun visitElement(element: PsiElement) {
                if (isJavaScriptFile(element.containingFile)) {
                    visitJavaScriptElement(element, holder)
                }
                super.visitElement(element)
            }
        }
    }
    
    /**
     * Override this method to implement element-level rule checking
     */
    open fun visitJavaScriptElement(element: PsiElement, holder: ProblemsHolder) {
        // Default implementation does nothing
    }
    
    /**
     * Override this method to implement rule-specific logic
     */
    abstract fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder)
    
    /**
     * Checks if the file is a JavaScript or TypeScript file
     */
    protected fun isJavaScriptFile(file: PsiFile): Boolean {
        val fileName = file.name.lowercase()
        return fileName.endsWith(".js") || 
               fileName.endsWith(".ts") || 
               fileName.endsWith(".jsx") || 
               fileName.endsWith(".tsx")
    }
    

    
    /**
     * Helper method to find function calls by name
     */
    protected fun findFunctionCalls(file: PsiFile, functionNames: Set<String>): List<PsiElement> {
        val calls = mutableListOf<PsiElement>()
        
        file.accept(object : PsiElementVisitor() {
            override fun visitElement(element: PsiElement) {
                val text = element.text
                
                // Look for function calls
                functionNames.forEach { functionName ->
                    if (text.contains(functionName) && text.contains("(")) {
                        // Basic check for function call pattern
                        val pattern = Regex("""$functionName\s*\(""")
                        if (pattern.containsMatchIn(text)) {
                            calls.add(element)
                        }
                    }
                }
                
                super.visitElement(element)
            }
        })
        
        return calls
    }
    
    /**
     * Helper method to extract arguments from function calls
     */
    protected fun extractFunctionArguments(element: PsiElement): List<String> {
        val arguments = mutableListOf<String>()
        val text = element.text
        
        // Simple argument extraction (can be improved)
        val startIndex = text.indexOf('(')
        val endIndex = text.lastIndexOf(')')
        
        if (startIndex != -1 && endIndex != -1 && endIndex > startIndex) {
            val argsString = text.substring(startIndex + 1, endIndex)
            if (argsString.isNotBlank()) {
                arguments.addAll(argsString.split(',').map { it.trim() })
            }
        }
        
        return arguments
    }
    
    /**
     * Data class representing a detected prohibited operation with its position and context.
     * This is used across different database rule inspections to track violations.
     */
    data class ProhibitedOperation(
        val operationName: String,    // e.g., "fileIo.open", "fopen", "file.close"
        val startPos: Int,           // Absolute position in original file
        val endPos: Int,             // End position for highlighting
        val fullMatch: String,       // Complete matched text including parameters
        val parameters: String,      // Extracted parameters for analysis
        val objectName: String? = null  // For object methods like "file.close()", this is "file"
    )
    
    /**
     * Removes both single-line (//) and multi-line (/* */) comments from JavaScript code.
     * 
     * This method handles:
     * - Single-line comments: // comment
     * - Multi-line comments: /* comment */
     * - Nested comments and edge cases
     * - Preserves string literals and regex patterns
     * - Maintains original character positions for accurate error reporting
     * 
     * @param code The original JavaScript/TypeScript code
     * @return Code with comments removed, preserving original character positions
     */
    protected fun removeComments(code: String): String {
        val result = StringBuilder()
        var i = 0
        var inString = false
        var stringChar = ' '
        
        while (i < code.length) {
            val char = code[i]
            
            when {
                // Handle string literals - don't remove "comments" inside strings
                !inString && (char == '"' || char == '\'') -> {
                    inString = true
                    stringChar = char
                    result.append(char)
                }
                inString && char == stringChar && (i == 0 || code[i-1] != '\\') -> {
                    inString = false
                    result.append(char)
                }
                inString -> {
                    result.append(char)
                }
                // Handle single-line comments
                !inString && i < code.length - 1 && char == '/' && code[i + 1] == '/' -> {
                    // Skip to end of line, but preserve newline for position tracking
                    while (i < code.length && code[i] != '\n') {
                        result.append(' ') // Replace with spaces to maintain positions
                        i++
                    }
                    if (i < code.length) {
                        result.append(code[i]) // Preserve newline
                    }
                }
                // Handle multi-line comments
                !inString && i < code.length - 1 && char == '/' && code[i + 1] == '*' -> {
                    // Skip to */ but preserve structure for position tracking
                    result.append(' ') // Replace / with space
                    i++
                    result.append(' ') // Replace * with space
                    i++
                    
                    while (i < code.length - 1) {
                        if (code[i] == '*' && code[i + 1] == '/') {
                            result.append(' ') // Replace * with space
                            i++
                            result.append(' ') // Replace / with space
                            break
                        } else if (code[i] == '\n') {
                            result.append('\n') // Preserve newlines
                        } else {
                            result.append(' ') // Replace comment content with spaces
                        }
                        i++
                    }
                }
                else -> {
                    result.append(char)
                }
            }
            i++
        }
        
        return result.toString()
    }
    
    /**
     * Enhanced problem descriptor creation with TextRange support for precise highlighting.
     * 
     * @param element The PSI element where the problem occurs
     * @param message The violation message
     * @param holder The ProblemsHolder to register with
     * @param textRange Optional TextRange for precise highlighting
     * @param fixes Array of quick fixes for the violation
     */
    protected fun createProblemDescriptor(
        element: PsiElement,
        message: String,
        holder: ProblemsHolder,
        textRange: TextRange? = null,
        fixes: Array<LocalQuickFix> = emptyArray()
    ) {
        val fullMessage = "Database Rule ${getRuleNumber()}: $message"
        
        if (textRange != null) {
            holder.registerProblem(
                element,
                fullMessage,
                ProblemHighlightType.WARNING,
                textRange,
                *fixes
            )
        } else {
            holder.registerProblem(
                element,
                fullMessage,
                ProblemHighlightType.WARNING,
                *fixes
            )
        }
    }
    
    /**
     * Helper method to find variables that are assigned the result of database-related operations.
     * 
     * @param code The code to analyze
     * @param operations List of operations to check for in assignments
     * @return Set of variable names that hold database-related values
     */
    protected fun findVariableAssignments(code: String, operations: List<ProhibitedOperation>): Set<String> {
        val variables = mutableSetOf<String>()
        
        val assignmentPatterns = listOf(
            // Regular assignment: const variable = operation(...)
            Regex("""(const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*([^;\n]+)""", RegexOption.MULTILINE),
            // Await assignment: const variable = await operation(...)
            Regex("""(const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*await\s+([^;\n]+)""", RegexOption.MULTILINE)
        )
        
        for (pattern in assignmentPatterns) {
            pattern.findAll(code).forEach { match ->
                val variableName = match.groupValues[2]
                val assignmentExpression = match.groupValues.getOrNull(3)?.trim() ?: ""
                
                // Check if this assignment contains any of the specified operations
                for (operation in operations) {
                    if (isOperationInExpression(operation, assignmentExpression)) {
                        variables.add(variableName)
                        break
                    }
                }
            }
        }
        
        return variables
    }
    
    /**
     * Helper method to check if a specific operation appears in an assignment expression.
     * 
     * @param operation The operation to look for
     * @param expression The assignment expression to search in
     * @return true if the operation appears in the expression
     */
    protected fun isOperationInExpression(operation: ProhibitedOperation, expression: String): Boolean {
        return expression.contains(operation.fullMatch) || 
               (expression.contains(operation.operationName + "(") && 
                operation.parameters.isNotEmpty() && 
                expression.contains(operation.parameters))
    }
    
    /**
     * Reports a database rule violation to IntelliJ's problem reporting system with precise highlighting.
     *
     * @param operation The prohibited operation that violates the rule
     * @param file The file containing the violation
     * @param holder The ProblemsHolder to register the violation with
     * @param customMessage Optional custom message for the violation
     */
    protected fun reportViolation(
        operation: ProhibitedOperation, 
        file: PsiFile, 
        holder: ProblemsHolder,
        customMessage: String? = null
    ) {
        val targetElement = file.findElementAt(operation.startPos) ?: file.firstChild

        if (targetElement != null) {
            val elementRange = targetElement.textRange
            val elementStartOffset = elementRange.startOffset
            val elementLength = targetElement.textLength

            // Calculate relative coordinates for TextRange
            val relativeStart = operation.startPos - elementStartOffset
            val relativeEnd = operation.endPos - elementStartOffset

            // Validate range
            val isValidRange = relativeStart >= 0 &&
                    relativeEnd <= elementLength &&
                    relativeStart < relativeEnd

            val message = customMessage ?: getDefaultViolationMessage(operation)

            if (isValidRange) {
                val textRange = TextRange(relativeStart, relativeEnd)
                createProblemDescriptor(
                    element = targetElement,
                    message = message,
                    holder = holder,
                    textRange = textRange
                )
            } else {
                // Fallback without TextRange if range is invalid
                createProblemDescriptor(
                    element = targetElement,
                    message = message,
                    holder = holder
                )
            }
        }
    }
    
    /**
     * Get default violation message for a prohibited operation.
     * Subclasses can override this for rule-specific messages.
     * 
     * @param operation The prohibited operation
     * @return Default violation message
     */
    protected open fun getDefaultViolationMessage(operation: ProhibitedOperation): String {
        return "Prohibited use of '${operation.operationName}'. This violates database robustness rules."
    }
}