<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

/**
 * The outcome of the single GET made against one declared origin, plus whatever response
 * was captured.
 *
 * This is the shared artifact other rules assert over: status, headers and a body prefix
 * from one request, rather than each rule issuing its own and inventing its own silence
 * when the request fails.
 */
final class OriginProbeResult
{
    /**
     * @param  array<string, array<int, string>>  $headers  response headers, as Guzzle returned them
     * @param  string|null  $bodyPrefix  the first bytes of the body, or null when nothing was captured
     * @param  string|null  $redirectLocation  the Location header of a redirect, when there was one
     * @param  string|null  $failureMessage  why no response was captured, when none was
     * @param  bool  $loopback  whether the origin points at the machine running the analysis
     */
    public function __construct(
        public readonly DeclaredOrigin $declaredOrigin,
        public readonly string $probedUrl,
        public readonly OriginOutcome $outcome,
        public readonly ?int $statusCode = null,
        public readonly array $headers = [],
        public readonly ?string $bodyPrefix = null,
        public readonly ?string $redirectLocation = null,
        public readonly ?string $failureMessage = null,
        public readonly bool $loopback = false,
    ) {}

    public function origin(): string
    {
        return $this->declaredOrigin->origin;
    }

    /**
     * The same captured evidence, attributed to a declaration carrying more sources.
     *
     * Used when a later caller names the same origin through a different config value: the
     * origin is not probed again, but the report should still say every declaration it
     * came from.
     */
    public function withDeclaredOrigin(DeclaredOrigin $declaredOrigin): self
    {
        return new self(
            declaredOrigin: $declaredOrigin,
            probedUrl: $this->probedUrl,
            outcome: $this->outcome,
            statusCode: $this->statusCode,
            headers: $this->headers,
            bodyPrefix: $this->bodyPrefix,
            redirectLocation: $this->redirectLocation,
            failureMessage: $this->failureMessage,
            loopback: $this->loopback,
        );
    }

    /**
     * Whether a real response was captured. False means no evidence was obtained.
     */
    public function hasEvidence(): bool
    {
        return $this->outcome->hasEvidence();
    }

    /**
     * First value of a response header, matched case-insensitively.
     */
    public function header(string $name): ?string
    {
        $values = $this->headerValues($name);

        return $values[0] ?? null;
    }

    /**
     * All values of a response header, matched case-insensitively.
     *
     * @return array<int, string>
     */
    public function headerValues(string $name): array
    {
        $needle = strtolower($name);

        foreach ($this->headers as $header => $values) {
            if (strtolower($header) === $needle) {
                return array_values($values);
            }
        }

        return [];
    }

    public function hasHeader(string $name): bool
    {
        return $this->headerValues($name) !== [];
    }

    /**
     * One line describing what happened, for report messages and issue text.
     */
    public function describe(): string
    {
        if (! $this->hasEvidence()) {
            $reason = $this->failureMessage === null ? '' : ": {$this->failureMessage}";

            return "{$this->probedUrl} — {$this->outcome->label()}{$reason}";
        }

        $status = $this->statusCode === null ? '' : " HTTP {$this->statusCode}";

        if ($this->outcome === OriginOutcome::RedirectedOffHost && $this->redirectLocation !== null) {
            return "{$this->probedUrl} — {$this->outcome->label()}{$status} to {$this->redirectLocation}";
        }

        return "{$this->probedUrl} — {$this->outcome->label()}{$status}";
    }
}
