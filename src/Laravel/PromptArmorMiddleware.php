<?php

declare(strict_types=1);

namespace PromptArmor\Laravel;

use Closure;
use Illuminate\Http\Request;
use PromptArmor\PromptArmor;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel middleware that automatically protects configurable request input keys
 * against prompt injection using the PromptArmor library.
 *
 * On detection of unsafe content the middleware aborts the request with a 403
 * response. The middleware respects the published prompt-armor config and can
 * be disabled per-environment.
 */
final class PromptArmorMiddleware
{
    private PromptArmor $armor;

    public function __construct(PromptArmor $armor = null)
    {
        $this->armor = $armor ?? new PromptArmor();
    }

    /**
     * Handle an incoming HTTP request.
     *
     * @param Request $request
     * @param Closure $next
     * @return mixed
     */
    public function handle(Request $request, Closure $next): mixed
    {
        $config = config('prompt-armor', []);

        if (empty($config['enabled'] ?? true)) {
            return $next($request);
        }

        $inputKeys = $config['input_keys'] ?? ['prompt', 'message', 'input', 'query', 'content'];
        $threshold = (float) ($config['risk_threshold'] ?? 0.65);
        $llmAudit = (bool) ($config['llm_enabled'] ?? false);

        // Update configuration for this request (immutable pattern)
        $this->armor = $this->armor->withConfig([
            'risk_threshold' => $threshold,
            'llm_enabled' => $llmAudit,
        ]);

        foreach ($inputKeys as $key) {
            if (!$request->has($key)) {
                continue;
            }

            $value = (string) $request->input($key);
            $value = trim($value);

            if ($value === '') {
                continue;
            }

            if (!$this->armor->isSafe($value)) {
                $report = $this->armor->analyze($value, [
                    'source' => 'http_request',
                    'ip' => $request->ip(),
                    'url' => $request->url(),
                    'untrusted' => true,
                ]);

                // Log the blocked attempt (using Laravel logger if available)
                if (function_exists('logger')) {
                    logger()->warning('Prompt injection blocked by middleware', $report->toArray());
                }

                abort(
                    Response::HTTP_FORBIDDEN,
                    'The request contains potentially malicious prompt content and has been blocked.'
                );
            }
        }

        return $next($request);
    }
}
