<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\Support\ClassHierarchyIndex;

class ClassHierarchyIndexTest extends TestCase
{
    public function test_folds_case_so_a_reference_finds_a_differently_spelled_declaration(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Models\BaseModel', null, [], true);
        $index->record('App\Models\Admin', 'App\Models\basemodel', [], true);

        $this->assertSame('App\Models\basemodel', $index->parentOf('APP\MODELS\ADMIN'));
        // descendantsOf() answers with folded keys: its caller indexes a payload filed under
        // the key record() returned.
        $this->assertSame(['app\models\admin'], array_keys($index->descendantsOf('app\models\BASEMODEL')));
    }

    public function test_reports_traits_before_the_parent(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Service', 'App\Base', ['App\Caches', 'App\Logs'], true);

        // PHP's own precedence: a trait a class uses overrides what it would have inherited.
        $this->assertSame(['App\Caches', 'App\Logs', 'App\Base'], $index->ancestorsOf('App\Service'));
    }

    public function test_a_name_it_has_never_seen_draws_from_nothing(): void
    {
        $index = new ClassHierarchyIndex;

        $this->assertSame([], $index->ancestorsOf('Vendor\Unscanned'));
        $this->assertNull($index->parentOf('Vendor\Unscanned'));
        $this->assertSame([], $index->descendantsOf('Vendor\Unscanned'));
    }

    public function test_a_trait_has_no_parent_and_that_reads_the_same_as_having_none(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Caches', null, ['App\Logs'], true);

        $this->assertNull($index->parentOf('App\Caches'));
        $this->assertSame(['App\Logs'], $index->ancestorsOf('App\Caches'));
    }

    public function test_a_redeclared_name_keeps_only_the_last_declarations_edges(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Thing', 'App\OldBase', [], true);

        // Read the reverse edges before the second declaration arrives, so the answer below
        // can only be right if recording discarded them rather than appending to them.
        $this->assertSame(['app\thing'], array_keys($index->descendantsOf('App\OldBase')));

        $index->record('App\Thing', 'App\NewBase', [], true);

        $this->assertSame([], $index->descendantsOf('App\OldBase'));
        $this->assertSame(['app\thing'], array_keys($index->descendantsOf('App\NewBase')));
    }

    public function test_reaches_both_the_users_of_a_trait_and_the_children_of_a_class(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Caches', null, [], true);
        $index->record('App\A', null, ['App\Caches'], true);
        $index->record('App\B', 'App\A', [], true);

        $this->assertSame(['app\a', 'app\b'], array_keys($index->descendantsOf('App\Caches')));
    }

    public function test_a_path_of_trait_uses_alone_is_told_apart_from_one_crossing_an_extends_edge(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Caches', null, [], true);
        $index->record('App\Inlined', null, ['App\Caches'], true);
        $index->record('App\Scoped', 'App\Inlined', [], true);

        // The flag carries PHP's scoping rule outwards: a trait's methods share the using
        // class's scope and read its private properties, a parent's methods do not.
        $this->assertSame(
            ['app\inlined' => true, 'app\scoped' => false],
            $index->descendantsOf('App\Caches'),
        );
    }

    public function test_a_declaration_reached_both_ways_is_reported_on_the_trait_only_path(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Caches', null, [], true);
        // Both uses the trait directly and extends a class that also uses it, so it is reached
        // by a trait-only path and by one crossing an extends edge. The wider view subsumes
        // the narrower one, whichever arrives first.
        $index->record('App\Middle', null, ['App\Caches'], true);
        $index->record('App\Both', 'App\Middle', ['App\Caches'], true);

        $reached = $index->descendantsOf('App\Caches');

        $this->assertTrue($reached['app\both']);
    }

    public function test_a_trait_only_path_arriving_second_widens_the_view_an_extends_edge_left(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Caches', null, [], true);
        // Scoped is reached first, so Both is reached through it by an extends edge before
        // any trait-only path gets there. Inlined then reaches the same declaration by trait
        // uses alone, and the wider view has to replace the narrower one that is already
        // recorded, which is the only path that reads a declaration twice.
        $index->record('App\Scoped', null, ['App\Caches'], true);
        $index->record('App\Inlined', null, ['App\Caches'], true);
        $index->record('App\Both', 'App\Scoped', ['App\Inlined'], true);

        $this->assertSame(
            ['app\scoped' => true, 'app\inlined' => true, 'app\both' => true],
            $index->descendantsOf('App\Caches'),
        );
    }

    public function test_terminates_on_a_hierarchy_that_refers_back_to_itself(): void
    {
        $index = new ClassHierarchyIndex;
        // PHP could not load this, but an AST can express it and half-edited source reaches
        // the scanner.
        $index->record('App\A', 'App\B', [], true);
        $index->record('App\B', 'App\A', [], true);

        // The seed is not its own descendant.
        $this->assertSame(['app\b'], array_keys($index->descendantsOf('App\A')));
    }

    public function test_a_declaration_the_pass_will_not_judge_does_not_answer_inwards(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Base', null, [], true);
        $index->record('Tests\Double', 'App\Base', [], false);
        $index->record('Tests\UsesTrait', null, ['App\Base'], false);

        // Left out of the reverse edges, so a fixture cannot settle a finding against the
        // production class it extends or the trait it uses.
        $this->assertSame([], $index->descendantsOf('App\Base'));

        // Still inherited from, because what a class inherits does not depend on where its
        // parent was written.
        $this->assertSame(['App\Base'], $index->ancestorsOf('Tests\Double'));
    }

    public function test_record_answers_with_the_key_a_caller_should_file_its_own_payload_under(): void
    {
        $index = new ClassHierarchyIndex;
        $index->record('App\Models\BaseModel', null, [], true);

        // A caller keeping a payload beside the graph indexes it by this return value and
        // reads it back with the keys descendantsOf() answers with. Returning the name
        // instead would leave the payload under a key the walk inwards never asks for.
        $key = $index->record('App\Models\Admin', 'App\Models\BaseModel', [], true);

        $this->assertSame('app\models\admin', $key);
        $this->assertSame([$key], array_keys($index->descendantsOf('App\Models\BaseModel')));
    }

    public function test_key_folds_case(): void
    {
        $this->assertSame('app\models\order', ClassHierarchyIndex::key('App\Models\Order'));
    }
}
