<?php

declare(strict_types=1);

namespace PromptArmor;

use InvalidArgumentException;
use RuntimeException;

/**
 * Responsible for sanitizing prompts by removing, redacting or escaping dangerous segments.
 *
 * Supports two modes:
 *   - 'strip': aggressively removes or replaces known malicious patterns (default)
 *   - 'escape': neutralizes delimiters and control words while preserving intent
 *
 * All methods are pure and thread-safe.
 */
final class Sanitizer
{
    /**
     * Sanitize a prompt using the selected strategy.
     *
     * @param string $prompt Raw prompt text.
     * @param string $mode Either 'strip' or 'escape'.
     * @return string Sanitized prompt.
     * @throws InvalidArgumentException on invalid input or unknown mode.
     */
    public function sanitize(string $prompt, string $mode = 'strip'): string
    {
        if (!is_string($prompt)) {
            throw new InvalidArgumentException('Prompt must be a string.');
        }

        $prompt = trim($prompt);
        if ($prompt === '') {
            return '';
        }

        if (strlen($prompt) > 10000) {
            throw new InvalidArgumentException('Prompt exceeds maximum allowed length of 10000 characters.');
        }

        return match (strtolower($mode)) {
            'strip' => $this->stripSystemCommands($this->removeDelimiters($prompt)),
            'escape' => $this->escape($prompt),
            default => throw new InvalidArgumentException(
                "Invalid sanitize mode '{$mode}'. Allowed values: 'strip', 'escape'."
            ),
        };
    }

    /**
     * Escapes dangerous delimiters and control sequences without removing content.
     *
     * Useful when preserving user intent is more important than complete removal.
     */
    public function escape(string $prompt): string
    {
        $replacements = [
            '###' => '[###]',
            '"""' => '\\"\\"\\"',
            '<<<' => '[<<<]',
            '>>>' => '[>>>]',
            '[SYSTEM]' => '[[SYSTEM]]',
            '[INST]' => '[[INST]]',
            '```' => '` ` `',
            '~~~' => '~ ~ ~',
            '---' => '- - -',
        ];

        $prompt = str_replace(array_keys($replacements), array_values($replacements), $prompt);

        // Neutralize common command starters while keeping surrounding text
        return preg_replace(
            '/\b(ignore all|disregard previous|override all|jailbreak|dan mode)\b/i',
            '[$1]',
            $prompt
        ) ?? $prompt;
    }

    /**
     * Removes or redacts common delimiter blocks that attackers use to separate instructions.
     */
    public function removeDelimiters(string $prompt): string
    {
        $patterns = [
            '/###.*?(?=###|$)/s' => '[REDACTED_DELIMITER]',
            '/""".*?(?=""")/s' => '[REDACTED_DELIMITER]',
            '/```[\s\S]*?```/s' => '[REDACTED_CODE_BLOCK]',
            '/<<<.+?>>>/s' => '[REDACTED_DELIMITER]',
            '/\[SYSTEM\].*?(?=\[SYSTEM\]|\z)/is' => '[REDACTED_SYSTEM]',
            '/\[INST\].*?(?=\[INST\]|\z)/is' => '[REDACTED_INST]',
        ];

        foreach ($patterns as $pattern => $replacement) {
            $prompt = preg_replace($pattern, $replacement, $prompt) ?? $prompt;
        }

        return $prompt;
    }

    /**
     * Strips or redacts known system commands, jailbreak phrases and instruction overrides.
     *
     * Uses regex with word boundaries to avoid over-matching legitimate text.
     */
    public function stripSystemCommands(string $prompt): string
    {
        $dangerousPatterns = [
            '/(?i)\b(ignore all previous|disregard previous|override all|forget all previous).*?[.!?]?/i' => '[REDACTED_COMMAND]',
            '/(?i)\b(do anything now|jailbreak|dan mode|developer mode|god mode|unrestricted mode)\b/i' => '[REDACTED_JAILBREAK]',
            '/(?i)\b(execute system|run shell|perform command|system prompt is|new instructions follow).*?\b/i' => '[REDACTED_COMMAND]',
            '/(?i)(change your behavior|new policy|updated rules).*?(follow|do this instead|ignore previous)/i' => '[REDACTED_INSTRUCTION]',
            '/(?i)\b(print|repeat|output).*?(your instructions|the system prompt|above text)/i' => '[REDACTED_LEAK_ATTEMPT]',
        ];

        foreach ($dangerousPatterns as $pattern => $replacement) {
            $prompt = preg_replace($pattern, $replacement, $prompt) ?? $prompt;
        }

        // Final cleanup of any double spaces or excessive whitespace created by redactions
        $prompt = preg_replace('/\s+/', ' ', $prompt) ?? $prompt;

        return trim($prompt);
    }
}
