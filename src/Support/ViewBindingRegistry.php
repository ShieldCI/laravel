<?php

declare(strict_types=1);

namespace ShieldCI\Support;

/**
 * Per-view, per-variable render bindings, with the merge policy that keeps Blade N+1 findings
 * conservative: a variable is analyzable only when every render site agrees on a known type, and
 * a relation eager-loaded on any path is treated as loaded on all.
 */
class ViewBindingRegistry
{
    /** @var array<string, array<string, list<ViewBinding>>> */
    private array $map = [];

    public function add(string $viewFile, string $var, ViewBinding $binding): void
    {
        $this->map[$viewFile][$var][] = $binding;
    }

    /**
     * @return array<string, array{type: ?string, eagerLoads: list<string>, source: string}>|null
     */
    public function resolve(string $viewFile): ?array
    {
        if (! isset($this->map[$viewFile])) {
            return null;
        }

        $result = [];
        foreach ($this->map[$viewFile] as $var => $bindings) {
            $type = $bindings[0]->type;
            $eager = [];
            $source = $bindings[0]->source;
            $unknown = false;

            foreach ($bindings as $binding) {
                if ($binding->type === null) {
                    $unknown = true;
                    break;
                }
                $eager = array_merge($eager, $binding->eagerLoads);
            }

            if ($unknown) {
                continue; // drop the variable — do not analyze it
            }

            $result[$var] = [
                'type' => $type,
                'eagerLoads' => array_values(array_unique($eager)),
                'source' => $source,
            ];
        }

        return $result;
    }
}
