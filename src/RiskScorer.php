<?php

declare(strict_types=1);

namespace PromptArmor;

use InvalidArgumentException;

/**
 * Calculates normalized risk scores (0.0-1.0) from detector signals and produces
 * human-readable explanations with per-signal breakdowns.
 *
 * The scoring applies diminishing returns for multiple signals and can be
 * influenced by optional context (e.g. source trustworthiness).
 */
final class RiskScorer
{
    private const DEFAULT_THRESHOLD = 0.65;

    /**
     * Calculate a normalized risk score in the range [0.0, 1.0].
     *
     * @param list<array<string, mixed>> $signals List of signals from detectors. Each signal must contain a 'weight' key.
     * @param array<string, mixed> $context Optional context (e.g. ['source' => 'user', 'untrusted' => true]).
     * @return float Risk score (0.0 = safe, 1.0 = certain injection).
     * @throws InvalidArgumentException if signals array is malformed.
     */
    public function calculate(array $signals, array $context = []): float
    {
        if (!array_is_list($signals)) {
            throw new InvalidArgumentException('Signals must be a list of arrays.');
        }

        foreach ($signals as $signal) {
            if (!is_array($signal) || !isset($signal['weight']) || !is_numeric($signal['weight'])) {
                throw new InvalidArgumentException(
                    'Each signal must be an array containing a numeric "weight" key.'
                );
            }
        }

        if ($signals === []) {
            return 0.0;
        }

        $totalWeight = 0.0;
        foreach ($signals as $signal) {
            $totalWeight += (float) $signal['weight'];
        }

        $signalCount = count($signals);
        $averageWeight = $totalWeight / $signalCount;

        // Diminishing returns: additional signals increase score but with logarithmic scaling
        $multiplier = min(1.8, 0.7 + log(1 + $signalCount) * 0.35);
        $score = $averageWeight * $multiplier;

        // Context-based adjustment
        if (isset($context['untrusted']) && $context['untrusted'] === true) {
            $score = min(1.0, $score * 1.25);
        }

        if (isset($context['user_reputation']) && is_numeric($context['user_reputation'])) {
            $reputationFactor = max(0.6, (float) $context['user_reputation']);
            $score *= (1.0 - ($reputationFactor * 0.3));
        }

        return min(1.0, max(0.0, $score));
    }

    /**
     * Generate a clear, actionable explanation from the collected signals.
     *
     * The explanation always highlights the highest-weight signal first and
     * includes a severity qualifier based on the computed score.
     *
     * @param list<array<string, mixed>> $signals
     * @return string Human-readable explanation.
     */
    public function generateExplanation(array $signals): string
    {
        if ($signals === []) {
            return 'No risky patterns detected. Prompt appears safe.';
        }

        // Sort signals by weight descending so the strongest signal leads the explanation
        usort($signals, static fn (array $a, array $b): int =>
            ((float) ($b['weight'] ?? 0.0)) <=> ((float) ($a['weight'] ?? 0.0))
        );

        $topSignal = $signals[0];
        $explanation = $topSignal['explanation'] ?? 'Risky content detected.';
        $score = $this->calculate($signals);

        if ($score >= 0.85) {
            $explanation .= ' High-confidence prompt injection attempt (score: ' . round($score, 2) . ').';
        } elseif ($score >= 0.55) {
            $explanation .= ' Moderate risk of prompt injection (score: ' . round($score, 2) . ').';
        } else {
            $explanation .= ' Minor risk signal present (score: ' . round($score, 2) . ').';
        }

        if (count($signals) > 2) {
            $explanation .= ' ' . (count($signals) - 1) . ' additional supporting indicators were found.';
        }

        return trim($explanation);
    }
}
