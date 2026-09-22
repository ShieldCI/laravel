<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

use ShieldCI\AnalyzersCore\Enums\Status;

/**
 * The result of probing every origin the application declares it is served from.
 *
 * The verdict this report carries is deliberately narrow: it says whether a response was
 * captured, never whether the response was good. What a captured response contains is for
 * the calling rule to judge, and it can only judge it because the response is here.
 *
 * The one rule that is not negotiable: this never reports Passed from zero responses. An
 * origin that could not be reached produces a Warning saying no evidence was obtained, so
 * a caller cannot mistake silence for success.
 */
final class OriginReachabilityReport
{
    /**
     * @param  array<int, OriginProbeResult>  $probes
     * @param  string|null  $environment  the application environment, when known (APP_ENV)
     * @param  array<int, string>  $unusableDeclarations  names of declarations that carried a
     *                                                    value naming no usable http(s) origin
     */
    public function __construct(
        private readonly array $probes,
        private readonly ?string $environment = null,
        private readonly array $unusableDeclarations = [],
    ) {}

    /**
     * Declarations that were present but named no origin that could be probed.
     *
     * @return array<int, string>
     */
    public function unusableDeclarations(): array
    {
        return $this->unusableDeclarations;
    }

    /**
     * @return array<int, OriginProbeResult>
     */
    public function probes(): array
    {
        return $this->probes;
    }

    /**
     * The probe of one origin, or null when that origin was never declared.
     */
    public function probeFor(string $origin): ?OriginProbeResult
    {
        foreach ($this->probes as $probe) {
            if ($probe->origin() === $origin) {
                return $probe;
            }
        }

        return null;
    }

    /**
     * Whether any origin at all produced a response a caller may assert over.
     */
    public function hasEvidence(): bool
    {
        return $this->withEvidence() !== [];
    }

    /**
     * Probes that captured a response.
     *
     * @return array<int, OriginProbeResult>
     */
    public function withEvidence(): array
    {
        return array_values(array_filter(
            $this->probes,
            static fn (OriginProbeResult $probe): bool => $probe->hasEvidence()
        ));
    }

    /**
     * Probes that captured nothing, and so prove nothing.
     *
     * @return array<int, OriginProbeResult>
     */
    public function withoutEvidence(): array
    {
        return array_values(array_filter(
            $this->probes,
            static fn (OriginProbeResult $probe): bool => ! $probe->hasEvidence()
        ));
    }

    /**
     * Origins that point at the machine running the analysis while the application claims
     * to be in production. Reaching one proves nothing about the deployed origin.
     *
     * @return array<int, OriginProbeResult>
     */
    public function loopbackInProduction(): array
    {
        if (! $this->isProduction()) {
            return [];
        }

        return array_values(array_filter(
            $this->probes,
            static fn (OriginProbeResult $probe): bool => $probe->loopback
        ));
    }

    /**
     * Passed only when every declared origin answered and none of them was a loopback
     * address in production. Otherwise a Warning, never a pass built on silence.
     */
    public function status(): Status
    {
        return $this->findings() === [] ? Status::Passed : Status::Warning;
    }

    /**
     * Every reason this report is not a clean pass, one sentence each.
     *
     * Empty when, and only when, the status is Passed.
     *
     * @return array<int, string>
     */
    public function findings(): array
    {
        if ($this->probes === [] && $this->unusableDeclarations === []) {
            return ['The application declares no origin it is served from, so no evidence was obtained about how it answers over HTTP.'];
        }

        $findings = [];

        // Reported before the probes: a declaration that could not be parsed is the reason
        // an origin is missing from the list below, and saying "nothing was declared" when
        // something was declared and is broken points the user away from the fault.
        foreach ($this->unusableDeclarations as $source) {
            $findings[] = sprintf(
                '%s is set to a value that is not a usable http or https origin, so it could not be probed and no evidence was obtained about it.',
                $source
            );
        }

        foreach ($this->withoutEvidence() as $probe) {
            $reason = $probe->failureMessage === null
                ? $probe->outcome->label()
                : "{$probe->outcome->label()}: {$probe->failureMessage}";

            $findings[] = sprintf(
                '%s (declared by %s) could not be reached: %s. No evidence was obtained about this origin.',
                $probe->origin(),
                $probe->declaredOrigin->describeSources(),
                $reason
            );
        }

        foreach ($this->loopbackInProduction() as $probe) {
            // Two different sentences because only one of them is true at a time. The probe
            // may have failed, and claiming "whatever answered is this machine" about a
            // connection that was refused is the report asserting a response it never got.
            $findings[] = sprintf(
                $probe->hasEvidence()
                    ? '%s (declared by %s) is a loopback address while the environment is %s. Whatever answered is this machine, not the deployed origin, so it is not evidence about production.'
                    : '%s (declared by %s) is a loopback address while the environment is %s. It names the machine running the analysis, so probing it could not have produced evidence about the deployed origin either way.',
                $probe->origin(),
                $probe->declaredOrigin->describeSources(),
                (string) $this->environment
            );
        }

        return $findings;
    }

    /**
     * One line summarising what the probes established.
     */
    public function message(): string
    {
        if ($this->probes === []) {
            return $this->unusableDeclarations === []
                ? 'No declared origin to probe; no evidence obtained.'
                : 'No declared origin could be probed; no evidence obtained.';
        }

        $reached = count($this->withEvidence());
        $total = count($this->probes);

        $summary = sprintf(
            'Probed %d declared %s; %d answered.',
            $total,
            $total === 1 ? 'origin' : 'origins',
            $reached
        );

        return $this->unusableDeclarations === []
            ? $summary
            : $summary.sprintf(' %d further %s unusable.', count($this->unusableDeclarations), count($this->unusableDeclarations) === 1 ? 'declaration is' : 'declarations are');
    }

    /**
     * The application environment the probes were interpreted against.
     */
    public function environment(): ?string
    {
        return $this->environment;
    }

    private function isProduction(): bool
    {
        if ($this->environment === null) {
            return false;
        }

        return in_array(strtolower($this->environment), ['production', 'prod'], true);
    }
}
