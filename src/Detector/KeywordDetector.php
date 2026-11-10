<?php

declare(strict_types=1);

namespace PromptArmor\Detector;

use InvalidArgumentException;
use PromptArmor\DetectionResult;

/**
 * Fast keyword/phrase scanner optimized for high-precision detection of common override
 * phrases, DAN-style jailbreaks, and system-level commands.
 *
 * Operates in linear time with simple string contains checks after lower-casing.
 * Complements the regex-heavy HeuristicDetector.
 */
final class KeywordDetector implements DetectorInterface
{
    /**
     * Comprehensive map of high-risk phrases to their risk weights.
     *
     * @var array<string, float>
     */
    private array $keywordMap;

    public function __construct()
    {
        $this->keywordMap = $this->getKeywordMap();
    }

    /**
     * Returns a map of 30+ high-precision phrases commonly used in prompt injections.
     *
     * @return array<string, float>
     */
    private function getKeywordMap(): array
    {
        return [
            'ignore all previous' => 0.95,
            'ignore previous instructions' => 0.94,
            'disregard previous' => 0.93,
            'disregard all previous' => 0.92,
            'override all' => 0.90,
            'override previous' => 0.89,
            'forget all previous' => 0.91,
            'new instructions' => 0.78,
            'new system instructions' => 0.85,
            'jailbreak' => 0.92,
            'dan mode' => 0.89,
            'do anything now' => 0.91,
            'unrestricted mode' => 0.82,
            'no restrictions' => 0.83,
            'developer mode' => 0.87,
            'god mode' => 0.86,
            'system prompt' => 0.70,
            'print your instructions' => 0.88,
            'repeat the above' => 0.67,
            'repeat everything above' => 0.72,
            'output the above' => 0.65,
            'you are now' => 0.79,
            'from now on you are' => 0.81,
            'change your behavior' => 0.74,
            'bypass safety' => 0.85,
            'ignore safety' => 0.84,
            'remove all restrictions' => 0.90,
            'policy update' => 0.68,
            'updated policy' => 0.69,
            'new policy' => 0.66,
            'ceo says' => 0.55,
            'legal requirement' => 0.52,
            'emergency override' => 0.71,
            'test mode enabled' => 0.64,
        ];
    }

    public function detect(string $prompt, array $context = []): DetectionResult
    {
        if (!is_string($prompt)) {
            throw new InvalidArgumentException('Prompt must be a string.');
        }

        $prompt = trim($prompt);
        if ($prompt === '') {
            return new DetectionResult([]);
        }

        $signals = [];
        $lowerPrompt = strtolower($prompt);

        foreach ($this->keywordMap as $phrase => $weight) {
            if (str_contains($lowerPrompt, $phrase)) {
                $signals[] = [
                    'type' => 'keyword',
                    'name' => str_replace([' ', '\'', '"', '-'], '_', $phrase),
                    'weight' => $weight,
                    'matched_text' => $phrase,
                    'explanation' => "High-risk keyword/phrase '{$phrase}' detected.",
                ];
            }
        }

        // Additional keyword clusters that benefit from proximity checks
        if (str_contains($lowerPrompt, 'ignore') && str_contains($lowerPrompt, 'instructions')) {
            // Catch variations not covered by exact phrases
            if (!isset($this->keywordMap['ignore all previous'])) {
                $signals[] = [
                    'type' => 'keyword',
                    'name' => 'ignore_instructions',
                    'weight' => 0.80,
                    'matched_text' => 'ignore ... instructions',
                    'explanation' => "High-risk keyword combination 'ignore ... instructions' detected.",
                ];
            }
        }

        return new DetectionResult($signals);
    }
}
