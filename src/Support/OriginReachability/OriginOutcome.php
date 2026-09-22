<?php

declare(strict_types=1);

namespace ShieldCI\Support\OriginReachability;

/**
 * The named, distinguishable outcomes of a single origin probe.
 *
 * Every state is distinct on purpose. Collapsing "the server answered 403" into the same
 * bucket as "the name did not resolve" is what lets a caller report success from a probe
 * that never reached anything, which is the failure mode this helper exists to remove.
 */
enum OriginOutcome: string
{
    /** The origin answered, with a 2xx status. */
    case Connected2xx = 'connected_2xx';

    /** The origin answered, with a status outside 2xx (including a same-host redirect). */
    case ConnectedNon2xx = 'connected_non_2xx';

    /** The origin answered with a redirect pointing at a different host. */
    case RedirectedOffHost = 'redirected_off_host';

    /** The TLS handshake or certificate verification failed. */
    case TlsFailure = 'tls_failure';

    /** The host name could not be resolved. */
    case DnsFailure = 'dns_failure';

    /** The host resolved but refused the connection. */
    case ConnectionRefused = 'connection_refused';

    /** The connection or the response timed out. */
    case Timeout = 'timeout';

    /**
     * Transport failed for a reason none of the named states covers.
     *
     * Deliberately separate rather than folded into a neighbour: an unrecognised transport
     * error is still an absence of evidence, and mislabelling it would make the report lie
     * about what happened.
     */
    case TransportFailure = 'transport_failure';

    /**
     * Whether this outcome captured a real HTTP response that a caller may assert over.
     *
     * Only the connected states did. Everything else means no evidence was obtained, and a
     * caller must never report success from one.
     */
    public function hasEvidence(): bool
    {
        return match ($this) {
            self::Connected2xx, self::ConnectedNon2xx, self::RedirectedOffHost => true,
            default => false,
        };
    }

    /**
     * Short human-readable description, for report messages.
     */
    public function label(): string
    {
        return match ($this) {
            self::Connected2xx => 'connected (2xx)',
            self::ConnectedNon2xx => 'connected (non-2xx)',
            self::RedirectedOffHost => 'redirected off host',
            self::TlsFailure => 'TLS failure',
            self::DnsFailure => 'DNS failure',
            self::ConnectionRefused => 'connection refused',
            self::Timeout => 'timeout',
            self::TransportFailure => 'transport failure',
        };
    }
}
