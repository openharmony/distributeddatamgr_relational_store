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
 
package com.example.databasecheck.utils

import com.intellij.psi.PsiFile

/**
 * JavaScript code analysis utilities using string-based parsing.
 * 
 * This class provides JavaScript code analysis capabilities using regex-based parsing
 * to avoid PSI dependency issues while still providing structured analysis.
 * Supports function-scoped analysis to prevent cross-function variable contamination.
 */
object JavaScriptAnalyzer {
    
    /**
     * Data class representing a variable assignment in JavaScript code.
     */
    data class VariableAssignment(
        val variableName: String,
        val assignmentExpression: String,
        val startOffset: Int,
        val endOffset: Int,
        val functionScope: String? = null // The function this assignment belongs to
    )
    
    /**
     * Data class representing a function call in JavaScript code.
     */
    data class FunctionCall(
        val functionName: String,
        val arguments: List<String>,
        val startOffset: Int,
        val endOffset: Int,
        val objectName: String? = null, // For method calls like obj.method()
        val functionScope: String? = null // The function this call belongs to
    )
    
    /**
     * Data class representing a JavaScript function scope.
     */
    data class FunctionScope(
        val functionName: String,
        val startOffset: Int,      // Function declaration start
        val bodyStartOffset: Int,  // Function body start (after {)
        val endOffset: Int,        // Function end
        val body: String
    )
    
    /**
     * Extract all variable assignments from JavaScript code using regex parsing.
     * 
     * @param file The JavaScript file to analyze
     * @return List of variable assignments found in the file
     */
    fun extractVariableAssignments(file: PsiFile): List<VariableAssignment> {
        return extractVariableAssignmentsFromText(file.text)
    }

    /**
     * Extract all variable assignments from JavaScript code text using regex parsing.
     * 
     * @param code The JavaScript code text to analyze
     * @return List of variable assignments found in the code
     */
    fun extractVariableAssignmentsFromText(code: String): List<VariableAssignment> {
        val assignments = mutableListOf<VariableAssignment>()
        
        // Pattern for variable declarations: const/let/var variableName = expression
        val declarationPattern = Regex(
            """(const|let|var)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*([^;\n]+)""",
            RegexOption.MULTILINE
        )
        
        declarationPattern.findAll(code).forEach { match ->
            assignments.add(VariableAssignment(
                variableName = match.groupValues[2],
                assignmentExpression = match.groupValues[3].trim(),
                startOffset = match.range.first,
                endOffset = match.range.last + 1
            ))
        }
        
        // Pattern for assignment expressions: variableName = expression
        val assignmentPattern = Regex(
            """([a-zA-Z_$][a-zA-Z0-9_$]*)\s*=\s*([^;\n]+)""",
            RegexOption.MULTILINE
        )
        
        assignmentPattern.findAll(code).forEach { match ->
            // Skip if this is already captured as a declaration
            val precedingText = if (match.range.first > 10) {
                code.substring(match.range.first - 10, match.range.first)
            } else {
                code.substring(0, match.range.first)
            }
            
            if (!precedingText.contains(Regex("""(const|let|var)\s*$"""))) {
                assignments.add(VariableAssignment(
                    variableName = match.groupValues[1],
                    assignmentExpression = match.groupValues[2].trim(),
                    startOffset = match.range.first,
                    endOffset = match.range.last + 1
                ))
            }
        }
        
        return assignments
    }
    
    /**
     * Extract all function calls from JavaScript code using regex parsing.
     * 
     * @param file The JavaScript file to analyze
     * @return List of function calls found in the file
     */
    fun extractFunctionCalls(file: PsiFile): List<FunctionCall> {
        return extractFunctionCallsFromText(file.text)
    }

    /**
     * Extract all function calls from JavaScript code text using regex parsing.
     * 
     * @param code The JavaScript code text to analyze
     * @return List of function calls found in the code
     */
    fun extractFunctionCallsFromText(code: String): List<FunctionCall> {
        val calls = mutableListOf<FunctionCall>()
        
        // Pattern for method calls: object.method(args)
        val methodCallPattern = Regex(
            """([a-zA-Z_$][a-zA-Z0-9_$]*)\.([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)""",
            RegexOption.MULTILINE
        )
        
        methodCallPattern.findAll(code).forEach { match ->
            val objectName = match.groupValues[1]
            val methodName = match.groupValues[2]
            val argsString = match.groupValues[3]
            val args = if (argsString.isBlank()) emptyList() else 
                argsString.split(",").map { it.trim() }
            
            calls.add(FunctionCall(
                functionName = "$objectName.$methodName",
                arguments = args,
                startOffset = match.range.first,
                endOffset = match.range.last + 1,
                objectName = objectName
            ))
        }
        
        // Pattern for regular function calls: functionName(args)
        val functionCallPattern = Regex(
            """\b([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\(([^)]*)\)""",
            RegexOption.MULTILINE
        )
        
        functionCallPattern.findAll(code).forEach { match ->
            val functionName = match.groupValues[1]
            val argsString = match.groupValues[2]
            val args = if (argsString.isBlank()) emptyList() else 
                argsString.split(",").map { it.trim() }
            
            // Skip if this is already captured as a method call
            val precedingChar = if (match.range.first > 0) {
                code[match.range.first - 1]
            } else ' '
            
            if (precedingChar != '.') {
                calls.add(FunctionCall(
                    functionName = functionName,
                    arguments = args,
                    startOffset = match.range.first,
                    endOffset = match.range.last + 1
                ))
            }
        }
        
        return calls
    }
    
    /**
     * Check if a function call matches any of the prohibited operations.
     * 
     * @param call The function call to check
     * @param prohibitedOperations Set of prohibited operation names
     * @return true if the call matches a prohibited operation
     */
    fun isProhibitedOperation(call: FunctionCall, prohibitedOperations: Set<String>): Boolean {
        return prohibitedOperations.contains(call.functionName) ||
               prohibitedOperations.any { op -> call.functionName.endsWith(".$op") }
    }
    
    /**
     * Check if an expression contains database path patterns.
     * Enhanced to handle variable references and string concatenation.
     * 
     * @param expression The expression to check
     * @param databasePathPatterns List of regex patterns for database paths
     * @param variableAssignments Optional list of variable assignments for reference resolution
     * @return true if the expression contains database path patterns
     */
    fun containsDatabasePath(
        expression: String, 
        databasePathPatterns: List<Regex>,
        variableAssignments: List<VariableAssignment> = emptyList()
    ): Boolean {
        // Direct check: expression contains database path literals
        if (databasePathPatterns.any { pattern -> pattern.containsMatchIn(expression) }) {
            return true
        }
        
        // Variable reference check: resolve variables and check their values
        val variableReferences = extractVariableReferences(expression)
        for (variable in variableReferences) {
            // Find the variable assignment
            val assignment = variableAssignments.find { it.variableName == variable }
            if (assignment != null) {
                // Recursively check the assignment expression
                if (containsDatabasePath(assignment.assignmentExpression, databasePathPatterns, variableAssignments)) {
                    return true
                }
            }
        }
        
        return false
    }
    
    /**
     * Extract variable references from an expression string.
     * 
     * @param expression The expression to analyze
     * @return Set of variable names referenced in the expression
     */
    fun extractVariableReferences(expression: String): Set<String> {
        val variablePattern = Regex("""\b([a-zA-Z_$][a-zA-Z0-9_$]*)\b""")
        return variablePattern.findAll(expression).map { it.value }.toSet()
    }
    
    /**
     * Extract all function scopes from JavaScript code.
     * 
     * @param code The JavaScript code to analyze
     * @return List of function scopes found in the code
     */
    fun extractFunctionScopes(code: String): List<FunctionScope> {
        val scopes = mutableListOf<FunctionScope>()
        
        // Pattern for function declarations: function name(...) { ... }
        val functionPattern = Regex(
            """(async\s+)?function\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*\([^)]*\)\s*\{""",
            RegexOption.MULTILINE
        )
        
        functionPattern.findAll(code).forEach { match ->
            val functionName = match.groupValues[2]
            val startOffset = match.range.first
            val bodyStart = match.range.last + 1
            
            // Find the matching closing brace
            val endOffset = findMatchingCloseBrace(code, bodyStart - 1) // -1 because bodyStart is after {
            if (endOffset != -1) {
                val body = code.substring(bodyStart, endOffset)
                scopes.add(FunctionScope(
                    functionName = functionName,
                    startOffset = startOffset,
                    bodyStartOffset = bodyStart,
                    endOffset = endOffset + 1, // +1 to include the closing brace
                    body = body
                ))
            }
        }
        
        return scopes
    }
    
    /**
     * Find the matching closing brace for a given opening brace position.
     * 
     * @param code The JavaScript code
     * @param openBracePos The position of the opening brace
     * @return The position of the matching closing brace, or -1 if not found
     */
    private fun findMatchingCloseBrace(code: String, openBracePos: Int): Int {
        if (openBracePos >= code.length || code[openBracePos] != '{') {
            return -1
        }
        
        var braceCount = 1
        var inString = false
        var stringChar = ' '
        var i = openBracePos + 1
        
        while (i < code.length && braceCount > 0) {
            val char = code[i]
            
            when {
                !inString && (char == '"' || char == '\'') -> {
                    inString = true
                    stringChar = char
                }
                inString && char == stringChar && (i == 0 || code[i-1] != '\\') -> {
                    inString = false
                }
                !inString && char == '{' -> braceCount++
                !inString && char == '}' -> braceCount--
            }
            i++
        }
        
        return if (braceCount == 0) i - 1 else -1
    }
    
    /**
     * Extract function calls and assignments with function scope information.
     * 
     * @param code The JavaScript code to analyze
     * @return Pair of (function calls with scope, variable assignments with scope)
     */
    fun extractWithFunctionScopes(code: String): Pair<List<FunctionCall>, List<VariableAssignment>> {
        val functionScopes = extractFunctionScopes(code)
        val allCalls = mutableListOf<FunctionCall>()
        val allAssignments = mutableListOf<VariableAssignment>()
        
        // Process each function scope separately
        for (scope in functionScopes) {
            val scopeCalls = extractFunctionCallsFromText(scope.body)
            val scopeAssignments = extractVariableAssignmentsFromText(scope.body)
            
            // Add scope information and adjust offsets correctly
            scopeCalls.forEach { call ->
                allCalls.add(call.copy(
                    functionScope = scope.functionName,
                    startOffset = call.startOffset + scope.bodyStartOffset,
                    endOffset = call.endOffset + scope.bodyStartOffset
                ))
            }
            
            scopeAssignments.forEach { assignment ->
                allAssignments.add(assignment.copy(
                    startOffset = assignment.startOffset + scope.bodyStartOffset,
                    endOffset = assignment.endOffset + scope.bodyStartOffset,
                    functionScope = scope.functionName
                ))
            }
        }
        
        // Also process global scope (code outside functions)
        val globalCalls = extractFunctionCallsFromText(code)
        val globalAssignments = extractVariableAssignmentsFromText(code)
        
        // Filter out calls/assignments that are inside functions using bodyStartOffset and endOffset
        globalCalls.forEach { globalCall ->
            val isInFunction = functionScopes.any { scope ->
                globalCall.startOffset >= scope.bodyStartOffset && globalCall.endOffset <= scope.endOffset
            }
            if (!isInFunction) {
                allCalls.add(globalCall.copy(functionScope = null))
            }
        }
        
        globalAssignments.forEach { globalAssignment ->
            val isInFunction = functionScopes.any { scope ->
                globalAssignment.startOffset >= scope.bodyStartOffset && globalAssignment.endOffset <= scope.endOffset
            }
            if (!isInFunction) {
                allAssignments.add(globalAssignment)
            }
        }
        
        return Pair(allCalls, allAssignments)
    }
}