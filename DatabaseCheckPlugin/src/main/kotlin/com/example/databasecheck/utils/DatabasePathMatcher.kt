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

import com.intellij.psi.*
import com.intellij.psi.util.PsiTreeUtil

/**
 * Utility class for matching database paths in JavaScript code
 */
object DatabasePathMatcher {
    
    /**
     * Checks if a string literal represents a database path
     */
    fun isDatabasePath(pathString: String): Boolean {
        return DatabaseConstants.DATABASE_PATHS.any { pattern ->
            pattern.matches(pathString)
        }
    }
    
    /**
     * Checks if a PSI element contains a database path
     * Handles both string literals and concatenated expressions
     */
    fun containsDatabasePath(element: PsiElement): Boolean {
        return when {
            // Direct string literal
            isStringLiteral(element) -> {
                val stringValue = getStringValue(element)
                stringValue != null && isDatabasePath(stringValue)
            }
            
            // String concatenation or template
            isStringConcatenation(element) -> {
                hasStringConcatenationWithDatabasePath(element)
            }
            
            // Property access (context.databaseDir)
            isPropertyAccess(element) -> {
                isDatabaseDirAccess(element)
            }
            
            else -> false
        }
    }
    
    /**
     * Extracts all database paths from a PSI element
     */
    fun extractDatabasePaths(element: PsiElement): List<String> {
        val paths = mutableListOf<String>()
        
        // Traverse the element tree to find all path strings
        element.accept(object : PsiRecursiveElementVisitor() {
            override fun visitElement(element: PsiElement) {
                if (containsDatabasePath(element)) {
                    getStringValue(element)?.let { paths.add(it) }
                }
                super.visitElement(element)
            }
        })
        
        return paths
    }
    
    private fun isStringLiteral(element: PsiElement): Boolean {
        // For JavaScript: check if it's a string literal
        return element.text.startsWith("'") || element.text.startsWith("\"") || element.text.startsWith("`")
    }
    
    private fun getStringValue(element: PsiElement): String? {
        val text = element.text
        return when {
            text.startsWith("'") && text.endsWith("'") -> text.substring(1, text.length - 1)
            text.startsWith("\"") && text.endsWith("\"") -> text.substring(1, text.length - 1)
            text.startsWith("`") && text.endsWith("`") -> text.substring(1, text.length - 1)
            else -> null
        }
    }
    
    private fun isStringConcatenation(element: PsiElement): Boolean {
        // Look for binary expressions with + operator
        return element.text.contains("+") && 
               (element.text.contains("'") || element.text.contains("\"") || element.text.contains("`"))
    }
    
    private fun hasStringConcatenationWithDatabasePath(element: PsiElement): Boolean {
        val text = element.text
        
        // Check for common database path patterns in concatenations
        return text.contains("/data/storage/el") ||
               text.contains("/database/") ||
               text.contains("context.databaseDir") ||
               text.contains("context.currentHapModuleInfo.name")
    }
    
    private fun isPropertyAccess(element: PsiElement): Boolean {
        return element.text.contains(".")
    }
    
    private fun isDatabaseDirAccess(element: PsiElement): Boolean {
        return element.text.contains("context.databaseDir")
    }
}