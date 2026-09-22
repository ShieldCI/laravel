<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

/**
 * An origin the application declares it is served from, plus the declarations it came from.
 *
 * The origin is normalised to scheme://host[:port] with the default port for the scheme
 * elided, so two declarations that differ only by path collapse onto one origin and are
 * therefore probed once.
 */
final class DeclaredOrigin
{
    public const SOURCE_APP_URL = 'app.url';

    public const SOURCE_ASSET_URL = 'app.asset_url';

    public const SOURCE_VITE_MANIFEST = 'vite-manifest';

    public const SOURCE_MIX_MANIFEST = 'mix-manifest';

    /**
     * @param  array<int, string>  $sources  the declarations this origin was read from
     */
    public function __construct(
        public readonly string $origin,
        public readonly array $sources = [],
    ) {}

    /**
     * Host portion of the origin, without scheme or port.
     */
    public function host(): string
    {
        $host = parse_url($this->origin, PHP_URL_HOST);

        return is_string($host) ? $host : '';
    }

    /**
     * Human-readable list of the declarations this origin came from.
     */
    public function describeSources(): string
    {
        return $this->sources === [] ? 'an unnamed declaration' : implode(', ', $this->sources);
    }

    /**
     * Merge another declaration of the same origin, keeping the union of sources.
     */
    public function mergeSources(self $other): self
    {
        $sources = $this->sources;

        foreach ($other->sources as $source) {
            if (! in_array($source, $sources, true)) {
                $sources[] = $source;
            }
        }

        return new self($this->origin, $sources);
    }
}
