<?php

declare(strict_types=1);

namespace PromptArmor;

use JsonException;
use RuntimeException;

/**
 * Immutable value object representing a prompt analysis result.
 *
 * Contains the final risk score, safety verdict, explanations, matched
 * patterns, original prompt and sanitized output. Designed for logging,
 * policy decisions and audit trails.
 */
final class Report
{
    private readonly float $score;
    private readonly bool $safe;

    /** @var list<string> */
    private readonly array $explanations;

    /** @var list<array<string, mixed>> */
    private readonly array $matchedPatterns;

    private readonly string $originalPrompt;
    private readonly string $sanitizedPrompt;

    /**
     * @param list<array<string, mixed>> $matchedPatterns
     * @param string $explanation Primary explanation (wrapped into explanations array)
     */
    public function __construct(
        float $score,
        array $matchedPatterns,
        string $explanation,
        string $originalPrompt,
        string $sanitizedPrompt
    ) {
        $this->score = min(1.0, max(0.0, $score));
        $this->safe = $this->score < 0.65;
        $this->matchedPatterns = $this->validateMatchedPatterns($matchedPatterns);
        $this->explanations = [$explanation];
        $this->originalPrompt = $originalPrompt;
        $this->sanitizedPrompt = $sanitizedPrompt;
    }

    public function getScore(): float
    {
        return $this->score;
    }

    public function isSafe(): bool
    {
        return $this->safe;
    }

    /**
     * @return list<string>
     */
    public function getExplanations(): array
    {
        return $this->explanations;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function getMatchedPatterns(): array
    {
        return $this->matchedPatterns;
    }

    public function getOriginalPrompt(): string
    {
        return $this->originalPrompt;
    }

    public function getSanitizedPrompt(): string
    {
        return $this->sanitizedPrompt;
    }

    /**
     * Returns a serializable array representation of the report.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'score' => $this->score,
            'is_safe' => $this->safe,
            'explanations' => $this->explanations,
            'matched_patterns' => $this->matchedPatterns,
            'original_prompt' => $this->originalPrompt,
            'sanitized_prompt' => $this->sanitizedPrompt,
        ];
    }

    /**
     * Returns a pretty-printed JSON representation of the report.
     *
     * @throws RuntimeException if JSON encoding fails.
     */
    public function toJson(): string
    {
        try {
            return json_encode(
                $this->toArray(),
                JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES
            );
        } catch (JsonException $e) {
            throw new RuntimeException('Failed to encode report to JSON: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @param list<array<string, mixed>> $patterns
     * @return list<array<string, mixed>>
     */
    private function validateMatchedPatterns(array $patterns): array
    {
        foreach ($patterns as $pattern) {
            if (!is_array($pattern)) {
                throw new InvalidArgumentException('Every matched pattern must be an array.');
            }
        }

        return $patterns;
    }
}
