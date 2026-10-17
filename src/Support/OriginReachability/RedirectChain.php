<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

/**
 * The probes made while following same-host redirects from one URL, in the order they were
 * made, and why following stopped short when it did.
 *
 * The last probe is the answer: a 2xx is the page a browser would render, and anything else
 * is the reason no page was reached. The earlier probes are only the route there, kept so a
 * message can say where the request went rather than just where it ended.
 */
final class RedirectChain
{
    /** The next hop named a URL the chain had already visited. */
    public const STOPPED_AT_LOOP = 'loop';

    /** The chain reached the redirect limit with another same-host hop still to follow. */
    public const STOPPED_AT_LIMIT = 'limit';

    /**
     * @param  non-empty-list<OriginProbeResult>  $probes  every probe made, the first being the URL asked about
     * @param  self::STOPPED_AT_*|null  $stoppedBecause  why a same-host redirect was left unfollowed, when one was
     */
    public function __construct(
        public readonly array $probes,
        public readonly ?string $stoppedBecause = null,
    ) {}

    public function final(): OriginProbeResult
    {
        return $this->probes[count($this->probes) - 1];
    }

    /**
     * How many redirects were followed to reach the final probe.
     */
    public function redirectCount(): int
    {
        return count($this->probes) - 1;
    }

    /**
     * One line describing the route and where it ended, for report messages.
     *
     * A chain of one probe reads exactly as that probe does, so a caller moving onto this
     * from a single probe changes no message for a URL that never redirected.
     */
    public function describe(): string
    {
        $route = array_map(
            static fn (OriginProbeResult $probe): string => $probe->probedUrl,
            array_slice($this->probes, 0, -1),
        );

        $route[] = $this->final()->describe();
        $description = implode(' -> ', $route);

        return match ($this->stoppedBecause) {
            self::STOPPED_AT_LOOP => $description.', redirect loop',
            self::STOPPED_AT_LIMIT => sprintf('%s, stopped after %d same-host redirects', $description, $this->redirectCount()),
            default => $description,
        };
    }
}
