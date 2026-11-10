<?php

declare(strict_types=1);

namespace PromptArmor\Detector;

use InvalidArgumentException;
use PromptArmor\DetectionResult;

/**
 * Heuristic detector implementing 30+ common attack patterns with associated weights.
 *
 * Scans for instruction overrides, jailbreaks, delimiters, obfuscation, role assumption,
 * hypothetical framing, encoding tricks and many other injection vectors. Returns
 * weighted signals that feed into the RiskScorer.
 */
final class HeuristicDetector implements DetectorInterface
{
    /** @var list<array{name: string, regex: string, weight: float, explanation: string}> */
    private array $patterns;

    /**
     * @param list<array{name: string, regex: string, weight: float, explanation: string}> $customPatterns
     */
    public function __construct(array $customPatterns = [])
    {
        if (array_is_list($customPatterns) === false) {
            throw new InvalidArgumentException('Custom patterns must be a list of associative arrays.');
        }

        foreach ($customPatterns as $pattern) {
            if (!isset($pattern['name'], $pattern['regex'], $pattern['weight'], $pattern['explanation'])) {
                throw new InvalidArgumentException(
                    'Each custom pattern must contain keys: name, regex, weight, explanation.'
                );
            }
        }

        $this->patterns = array_merge($this->getBuiltInPatterns(), $customPatterns);
    }

    /**
     * Returns 30 built-in detection patterns covering the most common prompt injection techniques.
     *
     * Weights are tuned from real-world attack data (0.3 = low confidence, 0.95 = near-certain malice).
     *
     * @return list<array{name: string, regex: string, weight: float, explanation: string}>
     */
    private function getBuiltInPatterns(): array
    {
        return [
            [
                'name' => 'override_instructions',
                'regex' => '/(ignore|disregard|forget|override|neglect|stop|cease).*?(previous|above|prior|all|any|earlier).*?(instructions?|prompts?|rules?|guidelines?|constraints?|directives?)/i',
                'weight' => 0.92,
                'explanation' => 'Classic instruction override attempt detected.',
            ],
            [
                'name' => 'dan_jailbreak',
                'regex' => '/\b(DAN|do anything now|jailbreak|developer mode|god mode|unrestricted mode|sudo mode)\b/i',
                'weight' => 0.88,
                'explanation' => 'DAN-style or classic jailbreak phrase detected.',
            ],
            [
                'name' => 'role_assumption',
                'regex' => '/(you are now|act as if you are|pretend you are|assume you are|become|from now on you are).*?(admin|root|owner|developer|system|unrestricted|evil|helpful assistant without rules)/i',
                'weight' => 0.81,
                'explanation' => 'Unauthorized role assumption or privilege escalation detected.',
            ],
            [
                'name' => 'output_format_escape',
                'regex' => '/(output|respond|reply|answer).*?(only|exclusively|solely|just).*?(json|xml|markdown|code block|base64|encoded|plain text|raw)/i',
                'weight' => 0.67,
                'explanation' => 'Attempt to force specific output format that bypasses filters.',
            ],
            [
                'name' => 'delimiter_attack',
                'regex' => '/(###|===|\"\"\"|<<<|>>>|```|~~~|\[SYSTEM\]|\[INST\]|\[PROMPT\]|\[USER\]|\[ASSISTANT\]|<s>|<\|endoftext\|>|<\|im_start\|>)/i',
                'weight' => 0.74,
                'explanation' => 'Dangerous delimiter or separator used to separate instructions.',
            ],
            [
                'name' => 'system_command',
                'regex' => '/(execute|run|perform|invoke|call|use).*?(system|shell|command|query|sql|api|function|tool|os)/i',
                'weight' => 0.79,
                'explanation' => 'System or command execution language detected.',
            ],
            [
                'name' => 'repetition_attack',
                'regex' => '/(.{15,})\1{2,}/',
                'weight' => 0.45,
                'explanation' => 'Repetitive token pattern often used in injection attacks.',
            ],
            [
                'name' => 'base64_encoded',
                'regex' => '/(eyJ|eyJhbGci|eyJ0eXAi|[A-Za-z0-9+\/]{50,}={0,2})/i',
                'weight' => 0.55,
                'explanation' => 'Base64 encoded payload detected (common in obfuscated attacks).',
            ],
            [
                'name' => 'xml_instruction',
                'regex' => '/<\?xml|<\/?prompt|<\/?instruction|<\/?system|<\/?jailbreak|<\/?policy/i',
                'weight' => 0.72,
                'explanation' => 'XML-tagged instruction injection attempt.',
            ],
            [
                'name' => 'hypothetical_scenario',
                'regex' => '/(hypothetical|imagine if|what if|story where|fictionally|in a world where).*?(you|the ai|the model|assistant).*?(ignore|override|disregard|forget|not bound by)/i',
                'weight' => 0.63,
                'explanation' => 'Hypothetical framing used to bypass restrictions.',
            ],
            [
                'name' => 'translation_attack',
                'regex' => '/(translate|convert|encode|decode|rephrase).*?(following|this|the above).*?(to|into).*?(english|french|spanish|base64|hex|rot13|binary)/i',
                'weight' => 0.51,
                'explanation' => 'Translation trick often used to hide malicious intent.',
            ],
            [
                'name' => 'prompt_leak',
                'regex' => '/(repeat|print|output|echo|return|show|display).*?(your|the|above|previous).*?(instructions?|prompt|system prompt|rules|policy)/i',
                'weight' => 0.85,
                'explanation' => 'Attempt to make the model leak its own system prompt.',
            ],
            [
                'name' => 'persona_change',
                'regex' => '/(new persona|change your personality|you are now a|become a different|switch to|transform into).*?(helpful|evil|unrestricted|pirate|dan)/i',
                'weight' => 0.68,
                'explanation' => 'Attempt to change the AI\'s assigned persona.',
            ],
            [
                'name' => 'policy_bypass',
                'regex' => '/(bypass|circumvent|avoid|ignore|disable|remove).*?(safety|security|ethical|policy|guideline|filter|restriction|alignment)/i',
                'weight' => 0.89,
                'explanation' => 'Direct attempt to bypass safety policies.',
            ],
            [
                'name' => 'encoded_jailbreak',
                'regex' => '/(base64|rot13|hex|binary|leetspeak|morse).*?(decode|decrypt|interpret|translate).*?(this|following|below)/i',
                'weight' => 0.59,
                'explanation' => 'Obfuscated jailbreak using encoding schemes.',
            ],
            [
                'name' => 'authority_override',
                'regex' => '/(as an? (administrator|owner|developer|root|ceo|founder)|per updated policy|new company policy|according to new rules|legal requirement)/i',
                'weight' => 0.76,
                'explanation' => 'False authority claim to override normal behavior.',
            ],
            [
                'name' => 'emotional_manipulation',
                'regex' => '/(if you don\'t|unless you|or else a|this is very important to me|my life depends on|for the children|emergency)/i',
                'weight' => 0.48,
                'explanation' => 'Emotional manipulation or urgency to force compliance.',
            ],
            [
                'name' => 'multi_turn_injection',
                'regex' => '/(in your previous response|as you said before|continuing our last conversation|remember when you|earlier you agreed)/i',
                'weight' => 0.52,
                'explanation' => 'Multi-turn conversation manipulation attempt.',
            ],
            [
                'name' => 'code_interpreter',
                'regex' => '/(write|create|execute|run).*?(python|javascript|code|script|program|shell).*?(that|which).*?(does|performs|outputs|returns)/i',
                'weight' => 0.61,
                'explanation' => 'Attempt to use the model as a code interpreter for malicious purposes.',
            ],
            [
                'name' => 'token_smuggling',
                'regex' => '/(\[|\{|\()?(?:token|word|character|byte).*?(smuggle|hide|embed|insert|conceal).*?(\]|\}|\))?/i',
                'weight' => 0.44,
                'explanation' => 'Token smuggling or hidden instruction technique.',
            ],
            [
                'name' => 'format_escaping',
                'regex' => '/(markdown|html|json|yaml|xml).*?(injection|escape|breakout|override|ignore)/i',
                'weight' => 0.49,
                'explanation' => 'Format-specific escaping or injection attempt.',
            ],
            [
                'name' => 'long_prompt',
                'regex' => '/.{800,}/',
                'weight' => 0.35,
                'explanation' => 'Unusually long prompt that may be used to overwhelm content filters.',
            ],
            [
                'name' => 'url_indirect_injection',
                'regex' => '/https?:\/\/\S+\.(com|net|org|io|dev)\/.*?(prompt|injection|jailbreak|ignore|system)/i',
                'weight' => 0.57,
                'explanation' => 'Indirect prompt injection via external URL reference.',
            ],
            [
                'name' => 'character_substitution',
                'regex' => '/[A-Za-z0-9][!@#$%^&*()_+\-=\[\]{};\':"\\|,.<>\/?][A-Za-z0-9]/',
                'weight' => 0.31,
                'explanation' => 'Character substitution obfuscation often used to bypass keyword filters.',
            ],
            [
                'name' => 'test_prefix',
                'regex' => '/^(test|testing|ignore all rules above|begin test mode|simulation mode|dev mode)/i',
                'weight' => 0.66,
                'explanation' => 'Test mode or prefix used in many automated jailbreak templates.',
            ],
            [
                'name' => 'separator_injection',
                'regex' => '/(----|____|====|~~~~|\/\/\/\/).*(instructions|prompt|command|output|system|user)/i',
                'weight' => 0.53,
                'explanation' => 'Separator lines used to divide injected commands from user content.',
            ],
            [
                'name' => 'self_reference',
                'regex' => '/(you|the model|gpt|claude|llama|assistant).*?(must|should|will).*?(not|never|always).*?(reveal|say|output|tell|repeat)/i',
                'weight' => 0.47,
                'explanation' => 'Self-referential instructions attempting to control model behavior.',
            ],
            [
                'name' => 'universal_jailbreak',
                'regex' => '/(universal|grand|master|ultimate|perfect).*?(jailbreak|prompt|trick|hack|technique)/i',
                'weight' => 0.70,
                'explanation' => 'Reference to known universal jailbreak techniques.',
            ],
            [
                'name' => 'temperature_override',
                'regex' => '/(set|change|modify|adjust).*?(temperature|temp|creativity|top_p|top_k).*?(to| = |:)\s*(0|1|100|0\.|1\.)/i',
                'weight' => 0.41,
                'explanation' => 'Attempt to override model sampling parameters.',
            ],
            [
                'name' => 'context_injection',
                'regex' => '/(previous context|conversation history|system message).*?(is|was|contains).*?(ignore|replace|override)/i',
                'weight' => 0.64,
                'explanation' => 'Attempt to manipulate conversation context or history.',
            ],
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

        if (strlen($prompt) > 10000) {
            throw new InvalidArgumentException('Prompt exceeds maximum allowed length of 10000 characters.');
        }

        $signals = [];
        foreach ($this->patterns as $pattern) {
            if (preg_match($pattern['regex'], $prompt)) {
                $signals[] = [
                    'type' => 'heuristic',
                    'name' => $pattern['name'],
                    'weight' => $pattern['weight'],
                    'matched_text' => $this->extractMatch($prompt, $pattern['regex']),
                    'explanation' => $pattern['explanation'],
                ];
            }
        }

        // Additional fast heuristics that do not require complex regex
        if (strlen($prompt) > 1500) {
            $signals[] = [
                'type' => 'heuristic',
                'name' => 'excessive_length',
                'weight' => 0.38,
                'matched_text' => substr($prompt, 0, 50) . '...',
                'explanation' => 'Extremely long prompt - often used to overwhelm filters.',
            ];
        }

        $lowerPrompt = strtolower($prompt);
        if (preg_match('/\b(?:http|https|ftp):\/\/\S+/i', $prompt) && str_contains($lowerPrompt, 'prompt')) {
            $signals[] = [
                'type' => 'heuristic',
                'name' => 'url_with_prompt',
                'weight' => 0.42,
                'matched_text' => 'URL + prompt keyword',
                'explanation' => 'External URL combined with prompt language - common in indirect injection.',
            ];
        }

        // High density of special characters often indicates obfuscation
        $specialCharCount = preg_match_all('/[^\p{L}\p{N}\s]/u', $prompt);
        if ($specialCharCount > 45 && strlen($prompt) > 120) {
            $signals[] = [
                'type' => 'heuristic',
                'name' => 'high_special_char_density',
                'weight' => 0.39,
                'matched_text' => '(high special char count)',
                'explanation' => 'Unusually high density of special characters - often indicates obfuscation.',
            ];
        }

        return new DetectionResult($signals);
    }

    private function extractMatch(string $prompt, string $regex): string
    {
        if (preg_match($regex, $prompt, $matches)) {
            $match = $matches[0];
            return strlen($match) > 55 ? substr($match, 0, 52) . '...' : $match;
        }
        return '';
    }
}
