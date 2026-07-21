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
import com.intellij.psi.PsiElementVisitor

/**
 * Rule 2: Database File Copy Operations Detection
 *
 * This inspection detects violations of HarmonyOS Database Robustness Rule 2, which governs
 * database file copying operations and backup configurations.
 *
 * ## Rule Requirements:
 * 1. If using file interfaces to copy database files, ensure all database handles are closed
 * 2. Copy entire directory contents, not individual files
 * 3. Prefer RDB interfaces for backup/restore operations
 *
 * ## Detection Methods:
 * ### Method 1: Configuration Analysis
 * - Check resources/module.json for allowToBackupRestore settings
 * - Verify fullBackupOnly configuration
 * - Check excludes paths for database directories
 *
 * ### Method 2: Code Analysis
 * - Detect file copy operations on database paths
 * - Recommend RDB interfaces over file operations
 * - Check for proper database handle closure
 *
 * ## Violation Types:
 * - **Direct File Copy**: Using fileIo.copyFile on database paths
 * - **Unsafe Configuration**: Missing fullBackupOnly or excludes
 * - **Missing RDB Usage**: Not using rdbStore.backup/restore/clone
 *
 * @author Database Robustness Checker
 * @since 1.0
 */
class Rule2DatabaseCopyInspection : BaseDatabaseInspection() {

    override fun getRuleName(): String = "Database File Copy Operations"
    override fun getRuleNumber(): Int = 2
    override fun getDescription(): String =
        "Detects unsafe database file copy operations. " +
                "Recommends using RDB interfaces and proper backup configurations."

    override fun visitJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        analyzeJavaScriptFile(file, holder)
    }
    
    /**
     * Visit files to check both JavaScript and JSON configuration files.
     */
    override fun buildVisitor(holder: ProblemsHolder, isOnTheFly: Boolean): PsiElementVisitor {
        return object : PsiElementVisitor() {
            override fun visitFile(file: PsiFile) {
                when {
                    isJavaScriptFile(file) -> visitJavaScriptFile(file, holder)
                    isModuleJsonFile(file) -> visitModuleJsonFile(file, holder)
                }
            }
        }
    }
    
    /**
     * Check if the file is a module.json configuration file.
     */
    private fun isModuleJsonFile(file: PsiFile): Boolean {
        return file.name == "module.json" && 
               file.virtualFile?.path?.contains("resources/module.json") == true
    }
    
    /**
     * Visit module.json configuration files.
     */
    private fun visitModuleJsonFile(file: PsiFile, holder: ProblemsHolder) {
        val configContent = file.text
        val configViolations = analyzeModuleJsonConfig(configContent)
        
        for (violation in configViolations) {
            val message = "Configuration issue: ${violation.reason}"
            
            // For configuration files, highlight the entire file or specific elements
            val targetElement = file.firstChild ?: return
            createProblemDescriptor(
                element = targetElement,
                message = message,
                holder = holder
            )
        }
    }
    
    /**
     * Analyze JavaScript file for Rule2 violations.
     */
    private fun analyzeJavaScriptFile(file: PsiFile, holder: ProblemsHolder) {
        try {
            // Step 0: Remove comments to avoid parsing interference
            val originalText = file.text
            val codeWithoutComments = removeComments(originalText)
            
            // Step 1: Extract function calls and variable assignments with scope awareness
            val (functionCalls, variableAssignments) = JavaScriptAnalyzer.extractWithFunctionScopes(codeWithoutComments)
            
            // Step 2: Find file copy operations on database paths (with variable resolution)
            val fileCopyViolations = findFileCopyViolations(functionCalls, variableAssignments)
            
            // Step 3: Report JavaScript code violations only
            reportViolations(fileCopyViolations, file, holder)
            
        } catch (e: Exception) {
            // Fallback analysis for file copy operations
            fallbackFileCopyAnalysis(file, holder)
        }
    }

    /**
     * Find file copy operations that target database paths.
     * Enhanced to support variable reference resolution.
     */
    private fun findFileCopyViolations(
        calls: List<JavaScriptAnalyzer.FunctionCall>,
        variableAssignments: List<JavaScriptAnalyzer.VariableAssignment>
    ): List<DatabaseViolation> {
        val violations = mutableListOf<DatabaseViolation>()
        
        for (call in calls) {
            if (isFileCopyOperation(call.functionName)) {
                // Filter variable assignments to same function scope for accurate resolution
                val scopeAssignments = variableAssignments.filter { 
                    it.functionScope == call.functionScope 
                }
                
                // Check if any argument contains database paths (with variable resolution)
                val targetsDatabasePath = call.arguments.any { arg ->
                    JavaScriptAnalyzer.containsDatabasePath(arg, DatabaseConstants.DATABASE_PATHS, scopeAssignments)
                }
                
                if (targetsDatabasePath) {
                    violations.add(DatabaseViolation(
                        operation = createProhibitedOperation(call),
                        violationType = ViolationType.UNSAFE_FILE_COPY,
                        reason = "Using file interface to copy database files. " +
                                "Ensure all database handles are closed and consider using RDB interfaces."
                    ))
                }
            }
        }
        
        return violations
    }



    /**
     * Analyze module.json configuration content.
     */
    private fun analyzeModuleJsonConfig(configContent: String): List<DatabaseViolation> {
        val violations = mutableListOf<DatabaseViolation>()
        
        // Check for allowToBackupRestore configuration
        val hasAllowToBackup = configContent.contains("\"allowToBackupRestore\"")
        
        if (hasAllowToBackup) {
            val allowToBackupTrue = configContent.contains("\"allowToBackupRestore\"\\s*:\\s*true".toRegex())
            
            if (allowToBackupTrue) {
                // Check for fullBackupOnly
                val hasFullBackupOnly = configContent.contains("\"fullBackupOnly\"\\s*:\\s*true".toRegex())
                
                // Check for database excludes
                val hasEl1Exclude = configContent.contains("data/storage/el1/database/")
                val hasEl2Exclude = configContent.contains("data/storage/el2/database/")
                
                // If fullBackupOnly is not true AND excludes don't contain el1/el2 database paths
                if (!hasFullBackupOnly && !hasEl1Exclude && !hasEl2Exclude) {
                    violations.add(DatabaseViolation(
                        operation = ProhibitedOperation(
                            operationName = "allowToBackupRestore configuration",
                            startPos = 0,
                            endPos = 0,
                            fullMatch = "module.json config issue",
                            parameters = ""
                        ),
                        violationType = ViolationType.UNSAFE_BACKUP_CONFIG,
                        reason = "allowToBackupRestore is true but neither fullBackupOnly is set " +
                                "nor database paths are excluded. This may lead to database corruption."
                    ))
                }
                
                // Additional check: if fullBackupOnly is explicitly false
                val fullBackupOnlyFalse = configContent.contains("\"fullBackupOnly\"\\s*:\\s*false".toRegex())
                if (fullBackupOnlyFalse) {
                    violations.add(DatabaseViolation(
                        operation = ProhibitedOperation(
                            operationName = "fullBackupOnly configuration",
                            startPos = 0,
                            endPos = 0,
                            fullMatch = "fullBackupOnly: false",
                            parameters = ""
                        ),
                        violationType = ViolationType.UNSAFE_BACKUP_CONFIG,
                        reason = "fullBackupOnly is set to false, which may lead to incomplete database backup."
                    ))
                }
            }
        }
        
        return violations
    }

    /**
     * Check if a function name represents a file copy operation.
     */
    private fun isFileCopyOperation(functionName: String): Boolean {
        return DatabaseConstants.FILE_COPY_OPERATIONS.any { op ->
            functionName == op || functionName.endsWith(".$op")
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
    private fun reportViolations(violations: List<DatabaseViolation>, file: PsiFile, holder: ProblemsHolder) {
        for (violation in violations) {
            val message = when (violation.violationType) {
                ViolationType.UNSAFE_FILE_COPY -> 
                    "Unsafe database file copy operation '${violation.operation.operationName}'. ${violation.reason}"
                ViolationType.RECOMMEND_RDB_INTERFACE -> 
                    "Recommendation: ${violation.reason}"
                ViolationType.UNSAFE_BACKUP_CONFIG -> 
                    "Configuration issue: ${violation.reason}"
                ViolationType.CONFIG_CHECK_NEEDED -> 
                    "Configuration check needed: ${violation.reason}"
            }
            
            reportViolation(violation.operation, file, holder, message)
        }
    }

    /**
     * Fallback analysis for file copy operations if main analysis fails.
     */
    private fun fallbackFileCopyAnalysis(file: PsiFile, holder: ProblemsHolder) {
        val originalText = file.text
        val codeWithoutComments = removeComments(originalText)
        
        // Simple pattern matching for file copy operations
        for (operation in DatabaseConstants.FILE_COPY_OPERATIONS) {
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
                    
                    val message = "Unsafe database file copy operation '${prohibitedOp.operationName}' (fallback detection). " +
                            "Consider using RDB interfaces instead."
                    
                    reportViolation(prohibitedOp, file, holder, message)
                }
            }
        }
    }

    /**
     * Enhanced violation types for Rule2.
     */
    enum class ViolationType {
        UNSAFE_FILE_COPY,           // Direct file copy on database paths
        RECOMMEND_RDB_INTERFACE,    // Recommend RDB over file operations
        UNSAFE_BACKUP_CONFIG,       // Configuration issues in module.json
        CONFIG_CHECK_NEEDED         // Unable to verify configuration
    }

    /**
     * Database violation with enhanced type information.
     */
    data class DatabaseViolation(
        val operation: ProhibitedOperation,
        val violationType: ViolationType,
        val reason: String
    )
}